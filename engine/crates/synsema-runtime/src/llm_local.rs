//! Provider LLM `local` (spec LLM-LOCAL F1): inferencia GGUF cuantizada embebida en el
//! binario, CPU-only, vía candle. Cero red, cero server aparte, cero API key: un `.syn`
//! con `require llm` + `SYNSEMA_LLM_PROVIDER=local` + `SYNSEMA_LLM_MODEL=/ruta/modelo.gguf`
//! razona offline. Es el único provider que funciona con `deny net` total.
//!
//! Diseño (las decisiones importantes, en orden):
//! - **Carga LAZY y memoizada, UNA por proceso**: `wire_real_llm_provider` corre para TODOS
//!   los programas (y serve lo llama por intérprete), así que el modelo NO se carga en el
//!   wire sino en la primera op LLM, y el resultado (ok O error) queda en un cache
//!   process-wide por path (`LOADED`). Un `run` que no usa LLM no paga nada; un path roto
//!   no se reintenta por llamada; serve carga una sola vez para todos sus intérpretes.
//! - **Aislamiento de KV cache**: cada llamada arranca con `clear_kv_cache()` sobre la
//!   instancia que toma del pool — dos llamadas (consecutivas o concurrentes) JAMÁS
//!   comparten ni heredan estado de generación.
//! - **Concurrencia por pool-semáforo**: `SYNSEMA_LLM_MAX_CONCURRENT` (default 1) fija el
//!   máximo de instancias del modelo vivas. Con el default, requests simultáneos bajo
//!   serve se serializan (una instancia, cola FIFO por condvar). Subirlo crea instancias
//!   extra bajo demanda (re-lee el GGUF: RAM proporcional — opt-in consciente del usuario).
//! - **Tokenizer desde la metadata del GGUF** (`tokenizer.ggml.*`), sin sidecar
//!   `tokenizer.json`: se reconstruye un tokenizer HF serializando el JSON equivalente
//!   (BPE byte-level para vocabs "gpt2" —qwen/llama3—, Unigram+byte-fallback para "llama"
//!   —SPM/llama2—) y deserializándolo con la crate `tokenizers`. El pre-tokenizer es el
//!   ByteLevel estándar (aproximación deliberada: no replicamos el pre-tokenizer exacto
//!   por familia como llama.cpp; suficiente para chat).
//! - **Chat template hardcodeado por familia** (chatml/llama3/mistral/plain), detectado
//!   desde `tokenizer.chat_template` o el vocabulario — sin motor jinja en F1.
//! - **Greedy por default** (determinismo para agentes); `SYNSEMA_LLM_TEMPERATURE` > 0
//!   opta por muestreo (seed fija → reproducible).
//! - **Tool-calling prompteado** (los GGUF no tienen API de tools): `build_local_step_prompt`
//!   arma catálogo + formato JSON exigido y `parse_local_step` extrae la primera tool-call
//!   válida (pelando code fences) — ambas PURAS y testeadas sin modelo, patrón de la casa.
//! - **Errores NUNCA panican**: todo el camino devuelve `Final("[local error: …]")` con 0
//!   tokens, igual que los providers de red.
//! - **Streaming (`llm_stream`, F2)**: `call_stream` emite fragmentos a medida que se
//!   generan, con detokenización incremental (decode del acumulado + diff, reteniendo
//!   chars parciales — ver `generate`). El sink corre DENTRO del préstamo del pool:
//!   con `MAX_CONCURRENT=1` un cliente SSE lento serializa a los demás (mitigar es F3).

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use candle_core::quantized::gguf_file;
use candle_core::{Device, Tensor};
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::{quantized_llama, quantized_qwen2, quantized_qwen3};
use serde_json::{json, Map, Value};

use synsema_llm::provider::{
    LLMProvider, LLMRequest, LLMResponse, LlmStep, LlmStepResponse, ToolSpec,
};

/// Seed fija del sampler: con `SYNSEMA_LLM_TEMPERATURE` > 0 el muestreo sigue siendo
/// reproducible entre corridas (mismo binario + mismo prompt → misma salida).
const SAMPLER_SEED: u64 = 299_792_458;

/// Knobs del provider local (resueltos por `local_knobs_from_config` en `llm_providers`
/// con la precedencia environ > `.env` > default; ignorados por los providers de red).
#[derive(Clone, Debug, PartialEq)]
pub struct LocalKnobs {
    /// `SYNSEMA_LLM_CTX`: ventana de contexto a usar (capada al ctx del GGUF).
    pub ctx: usize,
    /// `SYNSEMA_LLM_THREADS`: threads del motor CPU (via `RAYON_NUM_THREADS`, aplicado
    /// antes de la primera carga; sin knob se usa el default de rayon = cores lógicos).
    pub threads: Option<usize>,
    /// `SYNSEMA_LLM_TEMPERATURE`: 0 = greedy (default); >0 = muestreo con seed fija.
    pub temperature: f64,
    /// `SYNSEMA_LLM_MAX_CONCURRENT`: instancias máximas del modelo (default 1 = serializa).
    pub max_concurrent: usize,
    /// `SYNSEMA_LLM_STREAM_BUFFER` (F3-A): chunks en vuelo entre la generación y la
    /// emisión de `call_stream`. El préstamo del pool se libera al terminar la
    /// GENERACIÓN aunque el cliente siga drenando; un consumidor lento bloquea al
    /// productor recién cuando el buffer se llena.
    pub stream_buffer: usize,
}

impl Default for LocalKnobs {
    fn default() -> Self {
        Self { ctx: 4096, threads: None, temperature: 0.0, max_concurrent: 1, stream_buffer: 32 }
    }
}

// =========================================================
// Cache process-wide de modelos cargados
// =========================================================

/// Cache de modelos cargados, UNA carga por path por proceso. El `Arc` se comparte entre
/// todos los providers/intérpretes (run, serve base + workers); el resultado se memoiza
/// también si es error (un path roto no se reintenta por llamada). La carga corre BAJO el
/// lock del map: llamadas concurrentes a la primera op LLM esperan la carga en curso en
/// vez de duplicarla.
static LOADED: OnceLock<Mutex<HashMap<String, Arc<Result<LoadedGguf, String>>>>> =
    OnceLock::new();

/// Toma un lock ignorando poison (el camino del provider no panica; si un test paniqueó
/// con el lock tomado, el estado sigue siendo usable).
fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Un GGUF cargado y listo: tokenizer + template + metadata inmutables compartidos, y el
/// pool de instancias del modelo (los pesos con su KV cache mutable por instancia).
struct LoadedGguf {
    path: String,
    arch: String,
    tokenizer: tokenizers::Tokenizer,
    template: ChatTemplate,
    /// Tokens que terminan la generación (eos del GGUF + el de cierre del template).
    eos_ids: Vec<u32>,
    bos_id: Option<u32>,
    add_bos: bool,
    /// Contexto máximo declarado por el GGUF (`{arch}.context_length`).
    model_ctx: usize,
    pool: ModelPool,
}

/// Pool-semáforo de instancias del modelo: `max` = `SYNSEMA_LLM_MAX_CONCURRENT`. Con el
/// default (1) equivale a un mutex con cola justa; con más, crea instancias bajo demanda
/// (cada una re-lee el GGUF → RAM proporcional, documentado como opt-in).
struct ModelPool {
    inner: Mutex<PoolInner>,
    cv: Condvar,
}

struct PoolInner {
    idle: Vec<GgufModel>,
    created: usize,
    max: usize,
}

/// Las arquitecturas GGUF cuantizadas soportadas en F1 (las que trae candle-transformers
/// con reset de KV público). Otras → error legible, jamás basura silenciosa.
enum GgufModel {
    Llama(quantized_llama::ModelWeights),
    Qwen2(quantized_qwen2::ModelWeights),
    Qwen3(quantized_qwen3::ModelWeights),
}

impl GgufModel {
    fn forward(&mut self, input: &Tensor, index_pos: usize) -> Result<Tensor, String> {
        match self {
            GgufModel::Llama(m) => m.forward(input, index_pos),
            GgufModel::Qwen2(m) => m.forward(input, index_pos),
            GgufModel::Qwen3(m) => m.forward(input, index_pos),
        }
        .map_err(|e| format!("forward: {}", e))
    }

    fn clear_kv_cache(&mut self) {
        match self {
            GgufModel::Llama(m) => m.clear_kv_cache(),
            GgufModel::Qwen2(m) => m.clear_kv_cache(),
            GgufModel::Qwen3(m) => m.clear_kv_cache(),
        }
    }
}

impl LoadedGguf {
    /// Toma una instancia del pool (creándola o esperando según `max`), corre `f` y la
    /// devuelve SIEMPRE (también si `f` falla). El aislamiento KV lo garantiza `generate`
    /// (clear al inicio); acá sólo va la disciplina de préstamo.
    fn with_model<T>(&self, f: impl FnOnce(&mut GgufModel) -> Result<T, String>) -> Result<T, String> {
        let mut m = self.acquire()?;
        let r = f(&mut m);
        let mut g = lock_unpoisoned(&self.pool.inner);
        g.idle.push(m);
        drop(g);
        self.pool.cv.notify_one();
        r
    }

    fn acquire(&self) -> Result<GgufModel, String> {
        let mut g = lock_unpoisoned(&self.pool.inner);
        loop {
            if let Some(m) = g.idle.pop() {
                return Ok(m);
            }
            if g.created < g.max {
                g.created += 1;
                drop(g);
                match build_model_instance(&self.path, &self.arch) {
                    Ok(m) => return Ok(m),
                    Err(e) => {
                        // Devolver el cupo para no encoger el pool para siempre.
                        let mut g = lock_unpoisoned(&self.pool.inner);
                        g.created -= 1;
                        drop(g);
                        self.pool.cv.notify_one();
                        return Err(e);
                    }
                }
            }
            g = self.pool.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }
}

// =========================================================
// Carga del GGUF
// =========================================================

fn read_content(path: &str) -> Result<(gguf_file::Content, File), String> {
    let mut file =
        File::open(path).map_err(|e| format!("no se pudo abrir el archivo: {}", e))?;
    let content = gguf_file::Content::read(&mut file)
        .map_err(|e| format!("no es un GGUF válido: {}", e))?;
    Ok((content, file))
}

/// Construye la instancia desde un `Content` + reader YA leídos (F3-C: la carga inicial
/// reusa la única pasada de `read_content` — los offsets de tensores en `Content` son
/// absolutos, así que el reader posicionado tras el header sirve tal cual).
fn build_model_from(
    content: gguf_file::Content,
    file: &mut File,
    arch: &str,
) -> Result<GgufModel, String> {
    let device = Device::Cpu;
    match arch {
        "llama" => quantized_llama::ModelWeights::from_gguf(content, file, &device)
            .map(GgufModel::Llama),
        "qwen2" => quantized_qwen2::ModelWeights::from_gguf(content, file, &device)
            .map(GgufModel::Qwen2),
        "qwen3" => quantized_qwen3::ModelWeights::from_gguf(content, file, &device)
            .map(GgufModel::Qwen3),
        other => {
            return Err(format!(
                "arquitectura '{}' no soportada por el provider local (soportadas: llama, qwen2, qwen3)",
                other
            ))
        }
    }
    .map_err(|e| format!("no se pudieron cargar los pesos: {}", e))
}

/// Crea UNA instancia del modelo (pesos + KV cache propio) leyendo el GGUF. Sólo la usa
/// el pool cuando CRECE (`max_concurrent > 1`, opt-in raro) — la carga inicial va por
/// `build_model_from` con el `Content` ya leído (F3-C: una sola lectura por carga).
fn build_model_instance(path: &str, arch: &str) -> Result<GgufModel, String> {
    let (content, mut file) = read_content(path)?;
    build_model_from(content, &mut file, arch)
}

/// Carga completa: metadata + tokenizer + template + primera instancia del modelo.
/// UNA sola lectura del GGUF (F3-C): el `Content`/reader de la pasada de metadata se
/// reusa para construir los pesos al final.
fn load_gguf(path: &str, max_concurrent: usize) -> Result<LoadedGguf, String> {
    let (content, mut file) = read_content(path)?;
    let md = &content.metadata;

    let arch = md
        .get("general.architecture")
        .and_then(|v| v.to_string().ok())
        .cloned()
        .ok_or_else(|| "GGUF sin `general.architecture` en la metadata".to_string())?;

    let model_ctx = md
        .get(&format!("{}.context_length", arch))
        .and_then(|v| v.to_u32().ok())
        .map(|n| n as usize)
        .unwrap_or(4096);

    let tokenizer = build_tokenizer_from_metadata(md)?;
    let template = detect_chat_template(md, &tokenizer);

    // EOS: el declarado por el GGUF + el token de cierre del template si existe en el
    // vocab (los GGUF de llama3/qwen a veces declaran sólo uno de los dos).
    let mut eos_ids: Vec<u32> = Vec::new();
    if let Some(id) = md.get("tokenizer.ggml.eos_token_id").and_then(|v| v.to_u32().ok()) {
        eos_ids.push(id);
    }
    for tok in template.stop_tokens() {
        if let Some(id) = tokenizer.token_to_id(tok) {
            if !eos_ids.contains(&id) {
                eos_ids.push(id);
            }
        }
    }
    if eos_ids.is_empty() {
        return Err("GGUF sin `tokenizer.ggml.eos_token_id` ni token de cierre conocido".to_string());
    }

    let bos_id = md.get("tokenizer.ggml.bos_token_id").and_then(|v| v.to_u32().ok());
    // Default de add_bos: los vocabs SPM ("llama") lo esperan; los BPE ("gpt2") no —
    // salvo que el GGUF lo declare explícito.
    let spm = md
        .get("tokenizer.ggml.model")
        .and_then(|v| v.to_string().ok())
        .map(|s| s == "llama")
        .unwrap_or(false);
    let add_bos = md
        .get("tokenizer.ggml.add_bos_token")
        .and_then(|v| v.to_bool().ok())
        .unwrap_or(spm);

    let first = build_model_from(content, &mut file, &arch)?;
    Ok(LoadedGguf {
        path: path.to_string(),
        arch,
        tokenizer,
        template,
        eos_ids,
        bos_id,
        add_bos,
        model_ctx,
        pool: ModelPool {
            inner: Mutex::new(PoolInner {
                idle: vec![first],
                created: 1,
                max: max_concurrent.max(1),
            }),
            cv: Condvar::new(),
        },
    })
}

// =========================================================
// Tokenizer desde la metadata GGUF (sin sidecar)
// =========================================================

fn md_str_vec(md: &HashMap<String, gguf_file::Value>, key: &str) -> Option<Vec<String>> {
    let vals = md.get(key)?.to_vec().ok()?;
    let mut out = Vec::with_capacity(vals.len());
    for v in vals {
        out.push(v.to_string().ok()?.clone());
    }
    Some(out)
}

fn md_i64_vec(md: &HashMap<String, gguf_file::Value>, key: &str) -> Option<Vec<i64>> {
    let vals = md.get(key)?.to_vec().ok()?;
    let mut out = Vec::with_capacity(vals.len());
    for v in vals {
        // El tipo declarado varía entre conversores (i32/u32); toleramos ambos.
        let n = v.to_i32().map(|n| n as i64).or_else(|_| v.to_u32().map(|n| n as i64)).ok()?;
        out.push(n);
    }
    Some(out)
}

fn md_f32_vec(md: &HashMap<String, gguf_file::Value>, key: &str) -> Option<Vec<f32>> {
    let vals = md.get(key)?.to_vec().ok()?;
    let mut out = Vec::with_capacity(vals.len());
    for v in vals {
        out.push(v.to_f32().ok()?);
    }
    Some(out)
}

/// Reconstruye un tokenizer HF desde `tokenizer.ggml.*`: arma el JSON equivalente a un
/// `tokenizer.json` y lo deserializa con la crate `tokenizers`. Dos familias:
/// - `"gpt2"` (qwen/llama3/…): BPE byte-level con `tokens` + `merges`.
/// - `"llama"` (SPM/llama2/mistral): Unigram con `tokens` + `scores` + byte-fallback.
///
/// Los tokens de control (`token_type == 3`) y user-defined (`== 4`) van como
/// `added_tokens` → los especiales del chat template tokenizan como UN token.
fn build_tokenizer_from_metadata(
    md: &HashMap<String, gguf_file::Value>,
) -> Result<tokenizers::Tokenizer, String> {
    let kind = md
        .get("tokenizer.ggml.model")
        .and_then(|v| v.to_string().ok())
        .cloned()
        .ok_or_else(|| "GGUF sin `tokenizer.ggml.model` en la metadata".to_string())?;
    let tokens = md_str_vec(md, "tokenizer.ggml.tokens")
        .ok_or_else(|| "GGUF sin `tokenizer.ggml.tokens` en la metadata".to_string())?;
    let token_type = md_i64_vec(md, "tokenizer.ggml.token_type");

    // GGML token types: 1=normal, 2=unknown, 3=control, 4=user_defined, 5=unused, 6=byte.
    let mut added = Vec::new();
    if let Some(types) = &token_type {
        for (i, (tok, ty)) in tokens.iter().zip(types.iter()).enumerate() {
            if *ty == 3 || *ty == 4 {
                added.push(json!({
                    "id": i,
                    "content": tok,
                    "single_word": false,
                    "lstrip": false,
                    "rstrip": false,
                    "normalized": false,
                    "special": *ty == 3,
                }));
            }
        }
    }

    let tokenizer_json = match kind.as_str() {
        "gpt2" => {
            let merges_raw = md_str_vec(md, "tokenizer.ggml.merges")
                .ok_or_else(|| "GGUF con vocab gpt2 sin `tokenizer.ggml.merges`".to_string())?;
            let mut merges = Vec::with_capacity(merges_raw.len());
            for m in &merges_raw {
                let (a, b) = m
                    .split_once(' ')
                    .ok_or_else(|| format!("merge inválido en la metadata: '{}'", m))?;
                merges.push(json!([a, b]));
            }
            let mut vocab = Map::new();
            for (i, tok) in tokens.iter().enumerate() {
                vocab.insert(tok.clone(), json!(i));
            }
            json!({
                "version": "1.0",
                "added_tokens": added,
                "normalizer": null,
                "pre_tokenizer": {
                    "type": "ByteLevel",
                    "add_prefix_space": false,
                    "trim_offsets": true,
                    "use_regex": true,
                },
                "post_processor": null,
                "decoder": {
                    "type": "ByteLevel",
                    "add_prefix_space": true,
                    "trim_offsets": true,
                    "use_regex": true,
                },
                "model": {
                    "type": "BPE",
                    "dropout": null,
                    "unk_token": null,
                    "continuing_subword_prefix": null,
                    "end_of_word_suffix": null,
                    "fuse_unk": false,
                    "byte_fallback": false,
                    "ignore_merges": false,
                    "vocab": vocab,
                    "merges": merges,
                },
            })
        }
        "llama" => {
            let scores = md_f32_vec(md, "tokenizer.ggml.scores")
                .ok_or_else(|| "GGUF con vocab llama/SPM sin `tokenizer.ggml.scores`".to_string())?;
            if scores.len() != tokens.len() {
                return Err("metadata inconsistente: tokens y scores de distinto largo".to_string());
            }
            let vocab: Vec<Value> = tokens
                .iter()
                .zip(scores.iter())
                .map(|(t, s)| json!([t, s]))
                .collect();
            let unk_id = md
                .get("tokenizer.ggml.unknown_token_id")
                .and_then(|v| v.to_u32().ok())
                .unwrap_or(0);
            json!({
                "version": "1.0",
                "added_tokens": added,
                // SPM: espacio → ▁ (con prefijo), y el decoder deshace + byte-fallback.
                "normalizer": {
                    "type": "Sequence",
                    "normalizers": [
                        { "type": "Prepend", "prepend": "▁" },
                        { "type": "Replace", "pattern": { "String": " " }, "content": "▁" },
                    ],
                },
                "pre_tokenizer": null,
                "post_processor": null,
                "decoder": {
                    "type": "Sequence",
                    "decoders": [
                        { "type": "Replace", "pattern": { "String": "▁" }, "content": " " },
                        { "type": "ByteFallback" },
                        { "type": "Fuse" },
                        { "type": "Strip", "content": " ", "start": 1, "stop": 0 },
                    ],
                },
                "model": {
                    "type": "Unigram",
                    "unk_id": unk_id,
                    "vocab": vocab,
                    "byte_fallback": true,
                },
            })
        }
        other => {
            return Err(format!(
                "vocabulario '{}' no soportado por el provider local (soportados: gpt2, llama)",
                other
            ))
        }
    };

    serde_json::from_value::<tokenizers::Tokenizer>(tokenizer_json)
        .map_err(|e| format!("no se pudo reconstruir el tokenizer desde la metadata: {}", e))
}

// =========================================================
// Chat template (hardcodeado por familia — sin jinja en F1)
// =========================================================

/// Formato de conversación de la familia del modelo. Detectado desde la metadata
/// `tokenizer.chat_template` (string jinja que NO ejecutamos: sólo lo olfateamos) o,
/// si falta, desde el vocabulario. `Plain` = modelo base sin formato instruct.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ChatTemplate {
    ChatMl,
    Llama3,
    Mistral,
    Plain,
}

impl ChatTemplate {
    fn apply(&self, user: &str) -> String {
        match self {
            ChatTemplate::ChatMl => format!(
                "<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
                user
            ),
            ChatTemplate::Llama3 => format!(
                "<|start_header_id|>user<|end_header_id|>\n\n{}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
                user
            ),
            ChatTemplate::Mistral => format!("[INST] {} [/INST]", user),
            ChatTemplate::Plain => format!("{}\n", user),
        }
    }

    /// Tokens de cierre propios del template (se suman a los EOS del GGUF si existen).
    fn stop_tokens(&self) -> &'static [&'static str] {
        match self {
            ChatTemplate::ChatMl => &["<|im_end|>"],
            ChatTemplate::Llama3 => &["<|eot_id|>", "<|end_of_text|>"],
            ChatTemplate::Mistral => &["</s>"],
            ChatTemplate::Plain => &[],
        }
    }
}

fn detect_chat_template(
    md: &HashMap<String, gguf_file::Value>,
    tokenizer: &tokenizers::Tokenizer,
) -> ChatTemplate {
    if let Some(tpl) = md.get("tokenizer.chat_template").and_then(|v| v.to_string().ok()) {
        if tpl.contains("<|im_start|>") {
            return ChatTemplate::ChatMl;
        }
        if tpl.contains("<|start_header_id|>") {
            return ChatTemplate::Llama3;
        }
        if tpl.contains("[INST]") {
            return ChatTemplate::Mistral;
        }
    }
    if tokenizer.token_to_id("<|im_start|>").is_some() {
        return ChatTemplate::ChatMl;
    }
    if tokenizer.token_to_id("<|start_header_id|>").is_some() {
        return ChatTemplate::Llama3;
    }
    ChatTemplate::Plain
}

// =========================================================
// Generación
// =========================================================

/// Genera texto con una instancia prestada del pool. SIEMPRE arranca con
/// `clear_kv_cache()` → una llamada no puede ver tokens de otra (requisito §3.2).
/// Devuelve `(texto, tokens_usados = prompt + generados)`.
///
/// `sink` (F2, `llm_stream`): si está, cada fragmento de texto se emite a medida que se
/// genera, con **detokenización incremental correcta**: JAMÁS token-por-token suelto
/// (BPE byte-level y SPM parten chars multi-byte y pierden espacios) — se decodifica el
/// ACUMULADO y se emite el diff, reteniendo el final si termina en char parcial (`�`)
/// hasta que se complete (patrón TokenOutputStream de candle). Garantía verificada por
/// test: sin early-stop, la concatenación de los chunks == el retorno, byte-exacto (por
/// eso el camino con sink NO trimmea el resultado). Si el sink devuelve `false`
/// (p.ej. cliente SSE desconectado), la generación CORTA y se devuelve lo generado
/// hasta ahí — el aislamiento lo garantiza el `clear_kv_cache` de la PRÓXIMA llamada.
fn generate(
    loaded: &LoadedGguf,
    model: &mut GgufModel,
    user_text: &str,
    knobs: &LocalKnobs,
    max_tokens: u64,
    mut sink: Option<&mut dyn FnMut(&str) -> bool>,
) -> Result<(String, u64), String> {
    let prompt = loaded.template.apply(user_text);
    let enc = loaded
        .tokenizer
        .encode(prompt.as_str(), false)
        .map_err(|e| format!("tokenización: {}", e))?;
    let mut ids: Vec<u32> = enc.get_ids().to_vec();
    if loaded.add_bos {
        if let Some(b) = loaded.bos_id {
            if ids.first() != Some(&b) {
                ids.insert(0, b);
            }
        }
    }

    let ctx = knobs.ctx.min(loaded.model_ctx).max(16);
    if ids.len() >= ctx {
        return Err(format!(
            "el prompt ({} tokens) excede el contexto disponible ({} tokens)",
            ids.len(),
            ctx
        ));
    }
    let budget = (max_tokens as usize).min(ctx - ids.len());

    model.clear_kv_cache();
    let device = Device::Cpu;
    let mut sampler = if knobs.temperature > 0.0 {
        LogitsProcessor::from_sampling(
            SAMPLER_SEED,
            Sampling::All { temperature: knobs.temperature },
        )
    } else {
        LogitsProcessor::from_sampling(SAMPLER_SEED, Sampling::ArgMax)
    };

    // Prefill: todo el prompt en una pasada (index_pos 0); después token a token.
    let input = Tensor::new(ids.as_slice(), &device)
        .and_then(|t| t.unsqueeze(0))
        .map_err(|e| format!("prefill: {}", e))?;
    let logits = model.forward(&input, 0)?;
    let logits = logits.squeeze(0).map_err(|e| format!("prefill: {}", e))?;
    let mut next = sampler.sample(&logits).map_err(|e| format!("sampling: {}", e))?;

    let mut generated: Vec<u32> = Vec::new();
    let mut pos = ids.len();
    // Streaming: bytes del texto decodificado ya emitidos (offset sobre el decode
    // ACUMULADO — el prefijo ya decodificado es estable, sólo se appendea).
    let mut emitted = 0usize;
    let mut stopped = false;
    while generated.len() < budget {
        if loaded.eos_ids.contains(&next) {
            break;
        }
        generated.push(next);
        if let Some(s) = sink.as_deref_mut() {
            let so_far = loaded
                .tokenizer
                .decode(&generated, true)
                .map_err(|e| format!("detokenización: {}", e))?;
            // Emitir el diff sólo cuando creció y NO termina en char parcial (byte
            // partido de un multi-byte → `�`); si `emitted` no cae en un límite de char
            // (defensivo: el decoder reescribió el final), retener y reintentar después.
            if so_far.len() > emitted && !so_far.ends_with('\u{FFFD}') {
                if let Some(diff) = so_far.get(emitted..) {
                    emitted = so_far.len();
                    if !s(diff) {
                        stopped = true;
                        break;
                    }
                }
            }
        }
        let input = Tensor::new(&[next][..], &device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| format!("decode: {}", e))?;
        let logits = model.forward(&input, pos)?;
        let logits = logits.squeeze(0).map_err(|e| format!("decode: {}", e))?;
        next = sampler.sample(&logits).map_err(|e| format!("sampling: {}", e))?;
        pos += 1;
    }

    let text = loaded
        .tokenizer
        .decode(&generated, true)
        .map_err(|e| format!("detokenización: {}", e))?;
    let tokens = (ids.len() + generated.len()) as u64;
    if let Some(s) = sink.as_deref_mut() {
        // Flush del residuo retenido (char parcial al final, o el último token antes
        // del EOS) — así la concatenación de chunks == el retorno, byte-exacto. Tras un
        // early-stop no se emite más (el cliente ya no está); el retorno igual lleva
        // todo lo generado. El camino streaming NO trimmea (rompería la igualdad).
        if !stopped && text.len() > emitted {
            if let Some(rest) = text.get(emitted..) {
                let _ = s(rest);
            }
        }
        return Ok((text, tokens));
    }
    Ok((text.trim().to_string(), tokens))
}

// =========================================================
// Tool-calling prompteado (funciones PURAS, testeables sin modelo)
// =========================================================

/// Igual que `user_content` de los providers de red: prompt + contexto opcional.
fn local_user_content(user_prompt: &str, context: &str) -> String {
    if context.is_empty() {
        user_prompt.to_string()
    } else {
        format!("{}\n{}", user_prompt, context)
    }
}

/// Igual que `stringify_json` de los providers de red: strings sin comillas, el resto
/// serializado canónico.
fn local_stringify_json(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Arma el prompt del paso tool-aware: contenido del user + catálogo (name/description/
/// params) + formato exigido. En inglés: los GGUF chicos siguen instrucciones en inglés
/// mucho mejor que en otros idiomas.
pub fn build_local_step_prompt(prompt: &str, context: &str, tools: &[ToolSpec]) -> String {
    let user = local_user_content(prompt, context);
    if tools.is_empty() {
        return user;
    }
    let mut out = String::with_capacity(user.len() + 256);
    out.push_str(&user);
    out.push_str("\n\nYou have access to the following tools:\n");
    for t in tools {
        out.push_str("- ");
        out.push_str(&t.name);
        out.push_str(": ");
        out.push_str(&t.description);
        if !t.params.is_empty() {
            out.push_str(" (parameters: ");
            out.push_str(&t.params.join(", "));
            out.push(')');
        }
        out.push('\n');
    }
    out.push_str(
        "\nTo call a tool, reply with EXACTLY one JSON object on a single line and nothing else:\n\
         {\"tool\": \"<tool name>\", \"args\": {\"<parameter>\": \"<value>\"}}\n\
         If no tool is needed, reply directly with your final answer as plain text (no JSON).",
    );
    out
}

/// Quita las líneas de code fence (```…) — los modelos chicos envuelven el JSON en
/// fences aunque se les pida que no.
fn strip_code_fences(text: &str) -> String {
    if !text.contains("```") {
        return text.to_string();
    }
    text.lines()
        .filter(|l| !l.trim_start().starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Fin (inclusive) del objeto `{…}` balanceado que empieza en `start`, respetando
/// strings JSON con escapes. Los delimitadores son ASCII → los índices caen en límites
/// de char y el slicing es seguro.
fn find_balanced_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parsea la salida del modelo como un paso tool-aware: el PRIMER objeto JSON válido
/// (pelando code fences) cuyo `"tool"` matchee el catálogo → `ToolCall` (args
/// stringificados); cualquier otra cosa (texto plano, JSON malformado, tool inexistente)
/// → `Final` con el texto limpio.
pub fn parse_local_step(output: &str, tools: &[ToolSpec]) -> LlmStep {
    let clean = strip_code_fences(output);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = find_balanced_end(bytes, i) {
                if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&clean[i..=end]) {
                    if let Some(Value::String(name)) = m.get("tool") {
                        if tools.iter().any(|t| &t.name == name) {
                            let args = match m.get("args") {
                                Some(Value::Object(a)) => a
                                    .iter()
                                    .map(|(k, v)| (k.clone(), local_stringify_json(v)))
                                    .collect(),
                                _ => Vec::new(),
                            };
                            return LlmStep::ToolCall { name: name.clone(), args };
                        }
                    }
                }
            }
        }
        i += 1;
    }
    LlmStep::Final(clean.trim().to_string())
}

// =========================================================
// Puente generación→emisión con buffer acotado (F3-A)
// =========================================================

/// Corre `producer` en un hilo scoped y puentea sus chunks hacia `on_chunk` (invocado
/// en el hilo LLAMADOR) por un canal ACOTADO de `buffer` chunks. Semántica:
/// - El productor termina y suelta sus recursos (el préstamo del pool) aunque el
///   consumidor siga drenando el buffer — esa es la ganancia con `MAX_CONCURRENT=1`.
/// - Consumidor lento → el productor se bloquea recién con el buffer LLENO
///   (backpressure acotada, no cola infinita).
/// - `on_chunk` → `false` (o error del sink) → se dropea el receiver → el próximo
///   `send` del productor falla → su sink devuelve `false` → early-stop de F2 intacto,
///   ahora vía canal.
/// - `thread::scope` garantiza el join: ningún hilo sobrevive a la llamada.
/// - Orden y byte-exactitud: el canal es FIFO y no parte ni funde chunks.
fn pump_chunks<T: Send>(
    buffer: usize,
    producer: impl FnOnce(&mut dyn FnMut(&str) -> bool) -> T + Send,
    on_chunk: &mut dyn FnMut(&str) -> bool,
) -> Result<T, String> {
    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(buffer.max(1));
        // `tx` se mueve ENTERO al hilo productor (no queda copia acá): cuando el
        // productor termina, el canal se cierra y el drenaje de abajo corta solo.
        let gen = s.spawn(move || {
            producer(&mut |chunk: &str| tx.send(chunk.to_string()).is_ok())
        });
        for chunk in rx {
            if !on_chunk(&chunk) {
                break; // dropea `rx` → el productor ve el canal cerrado y corta
            }
        }
        gen.join().map_err(|_| "el hilo de generación abortó".to_string())
    })
}

// =========================================================
// El provider
// =========================================================

/// Provider LLM `local`: GGUF cuantizado embebido, CPU (candle). `Send + Sync`: el estado
/// mutable (instancias del modelo con su KV) vive en el pool del `LoadedGguf` compartido;
/// el provider en sí sólo guarda configuración inmutable.
pub struct LocalGgufProvider {
    model_path: String,
    /// Nombre del archivo (para `name()` y el campo `model` de las respuestas).
    file_name: String,
    max_tokens: u64,
    knobs: LocalKnobs,
}

impl LocalGgufProvider {
    pub fn new(model_path: String, max_tokens: u64, knobs: LocalKnobs) -> Self {
        let file_name = Path::new(&model_path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| model_path.clone());
        Self { model_path, file_name, max_tokens, knobs }
    }

    /// Carga lazy + memoizada (ver `LOADED`). El knob de threads se aplica ANTES de la
    /// primera operación de candle (después, el pool global de rayon ya quedó fijado).
    fn get_or_load(&self) -> Arc<Result<LoadedGguf, String>> {
        let map = LOADED.get_or_init(|| Mutex::new(HashMap::new()));
        let mut g = lock_unpoisoned(map);
        if let Some(a) = g.get(&self.model_path) {
            return a.clone();
        }
        if let Some(n) = self.knobs.threads {
            std::env::set_var("RAYON_NUM_THREADS", n.to_string());
        }
        let loaded = Arc::new(load_gguf(&self.model_path, self.knobs.max_concurrent));
        g.insert(self.model_path.clone(), loaded.clone());
        loaded
    }

    /// Camino común de generación: carga (memoizada) → instancia del pool → generate.
    /// `sink` (F2): pasarlo streamea los fragmentos a medida que se generan. OJO: la
    /// emisión corre DENTRO del préstamo del pool — con `SYNSEMA_LLM_MAX_CONCURRENT=1`
    /// (default), un consumidor lento del sink (p.ej. un cliente SSE lento) retiene la
    /// instancia y serializa a los demás. Desacoplarlo (buffer/canal) es F3, medido.
    fn generate_text(
        &self,
        user_text: &str,
        sink: Option<&mut dyn FnMut(&str) -> bool>,
    ) -> Result<(String, u64), String> {
        let arc = self.get_or_load();
        match arc.as_ref() {
            Err(e) => Err(format!("no se pudo cargar '{}': {}", self.model_path, e)),
            Ok(loaded) => loaded
                .with_model(|m| generate(loaded, m, user_text, &self.knobs, self.max_tokens, sink)),
        }
    }
}

impl LLMProvider for LocalGgufProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let user = local_user_content(&prompt, &context);
        let content = match self.generate_text(&user, None) {
            Ok((text, _)) => text,
            Err(e) => format!("[local error: {}]", e),
        };
        LLMResponse { content, model: self.file_name.clone() }
    }

    /// Streaming real (F2): el único provider que emite token a token. Los errores van
    /// como RETORNO `"[local error: …]"` (patrón de la casa), nunca por chunks.
    ///
    /// F3-A: la generación corre en un hilo scoped y los chunks pasan por un canal
    /// acotado (`SYNSEMA_LLM_STREAM_BUFFER`, default 32) — ver `pump_chunks`. El camino
    /// sin sink (`call`/`call_step`) no cambia ni un byte.
    fn call_stream(
        &self,
        request: &LLMRequest,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let user = local_user_content(&prompt, &context);
        let result = pump_chunks(
            self.knobs.stream_buffer,
            |sink| self.generate_text(&user, Some(sink)),
            on_chunk,
        );
        let content = match result {
            Ok(Ok((text, _))) => text,
            Ok(Err(e)) | Err(e) => format!("[local error: {}]", e),
        };
        LLMResponse { content, model: self.file_name.clone() }
    }

    fn name(&self) -> String {
        format!("local:{}", self.file_name)
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let step_prompt = build_local_step_prompt(&prompt, &context, &request.tools);
        match self.generate_text(&step_prompt, None) {
            Ok((text, tokens)) => LlmStepResponse {
                step: parse_local_step(&text, &request.tools),
                tokens_used: tokens,
            },
            Err(e) => LlmStepResponse {
                step: LlmStep::Final(format!("[local error: {}]", e)),
                tokens_used: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, desc: &str, params: &[&str]) -> ToolSpec {
        ToolSpec {
            name: name.to_string(),
            description: desc.to_string(),
            params: params.iter().map(|s| s.to_string()).collect(),
        }
    }

    // -- §4.1: build_local_step_prompt --

    #[test]
    fn step_prompt_includes_catalog_and_format() {
        let tools = [
            tool("get_weather", "get the weather", &["city"]),
            tool("send_mail", "send an email", &["to", "body"]),
        ];
        let p = build_local_step_prompt("What's the weather?", "ctx-here", &tools);
        assert!(p.contains("What's the weather?"));
        assert!(p.contains("ctx-here"));
        assert!(p.contains("get_weather") && p.contains("get the weather") && p.contains("city"));
        assert!(p.contains("send_mail") && p.contains("to, body"));
        assert!(p.contains("{\"tool\""), "debe exigir el formato JSON: {}", p);
    }

    #[test]
    fn step_prompt_without_tools_is_plain() {
        let p = build_local_step_prompt("hola", "", &[]);
        assert_eq!(p, "hola");
        let p2 = build_local_step_prompt("hola", "ctx", &[]);
        assert_eq!(p2, "hola\nctx");
    }

    // -- §4.2: parse_local_step --

    #[test]
    fn parse_clean_json_tool_call() {
        let tools = [tool("get_weather", "d", &["city"])];
        let step = parse_local_step(r#"{"tool": "get_weather", "args": {"city": "Madrid"}}"#, &tools);
        match step {
            LlmStep::ToolCall { name, args } => {
                assert_eq!(name, "get_weather");
                assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
            }
            _ => panic!("esperaba ToolCall, got {:?}", step),
        }
    }

    #[test]
    fn parse_json_in_code_fence() {
        let tools = [tool("get_weather", "d", &["city"])];
        let out = "```json\n{\"tool\": \"get_weather\", \"args\": {\"city\": \"Madrid\"}}\n```";
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { name, .. } => assert_eq!(name, "get_weather"),
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_json_embedded_in_prose() {
        let tools = [tool("get_weather", "d", &["city"])];
        let out = "Sure, let me check.\n{\"tool\": \"get_weather\", \"args\": {\"city\": \"Madrid\"}}\nDone.";
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { name, .. } => assert_eq!(name, "get_weather"),
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_tool_falls_to_final() {
        let tools = [tool("get_weather", "d", &["city"])];
        let out = r#"{"tool": "rm_rf", "args": {}}"#;
        match parse_local_step(out, &tools) {
            LlmStep::Final(t) => assert!(t.contains("rm_rf")),
            other => panic!("esperaba Final, got {:?}", other),
        }
    }

    #[test]
    fn parse_plain_text_is_final() {
        let tools = [tool("get_weather", "d", &["city"])];
        match parse_local_step("The weather is sunny.", &tools) {
            LlmStep::Final(t) => assert_eq!(t, "The weather is sunny."),
            other => panic!("esperaba Final, got {:?}", other),
        }
    }

    #[test]
    fn parse_malformed_json_is_final() {
        let tools = [tool("get_weather", "d", &["city"])];
        match parse_local_step(r#"{"tool": "get_weather", "args": {"#, &tools) {
            LlmStep::Final(_) => {}
            other => panic!("esperaba Final, got {:?}", other),
        }
    }

    #[test]
    fn parse_non_string_args_stringified() {
        let tools = [tool("calc", "d", &["n", "flag"])];
        let out = r#"{"tool": "calc", "args": {"n": 42, "flag": true, "obj": {"a": 1}}}"#;
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { args, .. } => {
                let get = |k: &str| args.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
                assert_eq!(get("n").as_deref(), Some("42"));
                assert_eq!(get("flag").as_deref(), Some("true"));
                assert_eq!(get("obj").as_deref(), Some(r#"{"a":1}"#));
            }
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_braces_inside_strings_dont_break_balance() {
        let tools = [tool("echo", "d", &["msg"])];
        let out = r#"{"tool": "echo", "args": {"msg": "a { b } c \" d"}}"#;
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { args, .. } => {
                assert_eq!(args[0].1, "a { b } c \" d");
            }
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    // -- Chat template: detección + formato --

    #[test]
    fn template_apply_shapes() {
        assert!(ChatTemplate::ChatMl.apply("hi").starts_with("<|im_start|>user\nhi"));
        assert!(ChatTemplate::ChatMl.apply("hi").ends_with("<|im_start|>assistant\n"));
        assert!(ChatTemplate::Llama3.apply("hi").contains("<|eot_id|>"));
        assert_eq!(ChatTemplate::Mistral.apply("hi"), "[INST] hi [/INST]");
        assert_eq!(ChatTemplate::Plain.apply("hi"), "hi\n");
    }

    // -- F3-A: pump_chunks (deterministas, sin modelo) --

    // Orden FIFO intacto y byte-exactitud: lo que el productor emite es lo que el
    // consumidor ve, chunk a chunk, y el retorno del productor llega entero.
    #[test]
    fn pump_chunks_order_and_exactness() {
        let chunks_in = ["Ho", "la", " mundo"];
        let mut got: Vec<String> = Vec::new();
        let r = pump_chunks(
            4,
            |sink| {
                let mut full = String::new();
                for c in chunks_in {
                    if !sink(c) {
                        break;
                    }
                    full.push_str(c);
                }
                full
            },
            &mut |c| {
                got.push(c.to_string());
                true
            },
        );
        assert_eq!(r.unwrap(), "Hola mundo");
        assert_eq!(got, vec!["Ho".to_string(), "la".to_string(), " mundo".to_string()]);
    }

    // Early-stop vía receiver dropeado: `on_chunk` → false al PRIMER chunk → el
    // productor ve el canal cerrado en su próximo send y corta (no produce los 5).
    #[test]
    fn pump_chunks_early_stop_via_receiver_drop() {
        let mut n = 0;
        let r = pump_chunks(
            1,
            |sink| {
                let mut sent = 0;
                for c in ["a", "b", "c", "d", "e"] {
                    if !sink(c) {
                        break;
                    }
                    sent += 1;
                }
                sent
            },
            &mut |_| {
                n += 1;
                false
            },
        );
        assert_eq!(n, 1, "el consumidor debía ver exactamente un chunk");
        // Con buffer 1 el productor puede colar a lo sumo un chunk extra antes de ver
        // el canal cerrado — pero jamás los cinco.
        assert!(r.unwrap() <= 2, "el productor debía cortar temprano");
    }

    // La ganancia F3-A: el productor TERMINA (y soltaría el préstamo del pool) mientras
    // el consumidor lento sigue drenando el buffer.
    #[test]
    fn pump_chunks_producer_finishes_before_slow_drain() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let done = AtomicBool::new(false);
        let mut last_saw_done = false;
        pump_chunks(
            32,
            |sink| {
                for c in ["a", "b", "c", "d"] {
                    sink(c);
                }
                done.store(true, Ordering::SeqCst);
            },
            &mut |_| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                last_saw_done = done.load(Ordering::SeqCst);
                true
            },
        )
        .unwrap();
        assert!(
            last_saw_done,
            "el productor debía terminar antes de que el consumidor lento drenara todo"
        );
    }

    // -- Tests en vivo (gated por SYNSEMA_TEST_GGUF; skip limpio si falta — patrón
    //    dev-db). El GGUF JAMÁS va al repo: bajalo a mano y exportá el path. --

    fn test_gguf_path() -> Option<String> {
        match std::env::var("SYNSEMA_TEST_GGUF") {
            Ok(p) if !p.trim().is_empty() => Some(p),
            _ => {
                eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/path/a/modelo.gguf para el test live");
                None
            }
        }
    }

    // §4.5: call() genera texto y dos llamadas consecutivas no se contaminan (KV aislado).
    #[test]
    fn live_call_generates_and_isolates_kv() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 64, LocalKnobs::default());
        let mut r1 = LLMRequest::new("reason");
        r1.data.insert("prompt".to_string(), "Reply with exactly one word: apple".to_string());
        let a = p.call(&r1);
        let mut r2 = LLMRequest::new("reason");
        r2.data.insert("prompt".to_string(), "Reply with exactly one word: banana".to_string());
        let b = p.call(&r2);
        assert!(!a.content.is_empty(), "primera respuesta vacía");
        assert!(!b.content.is_empty(), "segunda respuesta vacía");
        assert!(!a.content.starts_with("[local error"), "error: {}", a.content);
        assert!(!b.content.starts_with("[local error"), "error: {}", b.content);
        // Aislamiento: la segunda respuesta responde a SU prompt, no arrastra el primero.
        assert!(
            b.content.to_lowercase().contains("banana"),
            "la 2ª llamada no respondió a su prompt (¿KV contaminado?): {}",
            b.content
        );
    }

    // F2 §4.5: streaming real — ≥2 chunks para una respuesta multi-token, y la
    // concatenación de los chunks == el retorno, BYTE-exacto (la garantía de la
    // detokenización incremental).
    #[test]
    fn live_call_stream_chunks_concat_exact() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 64, LocalKnobs::default());
        let mut req = LLMRequest::new("stream");
        req.data.insert("prompt".to_string(), "Count from one to ten in words.".to_string());
        let mut chunks: Vec<String> = Vec::new();
        let resp = p.call_stream(&req, &mut |c| {
            chunks.push(c.to_string());
            true
        });
        assert!(!resp.content.starts_with("[local error"), "error: {}", resp.content);
        assert!(chunks.len() >= 2, "esperaba ≥2 chunks, got {}: {:?}", chunks.len(), chunks);
        assert_eq!(chunks.concat(), resp.content, "concat de chunks != retorno");
    }

    // F2 §4.6: early-stop — `on_chunk` → false tras el PRIMER chunk corta la generación
    // (sin panic), y la llamada SIGUIENTE no ve contaminación (KV aislado).
    #[test]
    fn live_call_stream_early_stop_and_isolation() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 64, LocalKnobs::default());
        let mut req = LLMRequest::new("stream");
        req.data
            .insert("prompt".to_string(), "Write a long story about the sea.".to_string());
        let mut n = 0;
        let resp = p.call_stream(&req, &mut |_| {
            n += 1;
            false
        });
        assert_eq!(n, 1, "debía cortar tras el primer chunk");
        assert!(
            resp.content.len() < 200,
            "cortó tarde ({} chars): {}",
            resp.content.len(),
            resp.content
        );
        let mut r2 = LLMRequest::new("reason");
        r2.data.insert("prompt".to_string(), "Reply with exactly one word: banana".to_string());
        let b = p.call(&r2);
        assert!(
            b.content.to_lowercase().contains("banana"),
            "la llamada post-corte no respondió a su prompt (¿KV contaminado?): {}",
            b.content
        );
    }

    // F3-A §5.2 (live): con MAX_CONCURRENT=1, una SEGUNDA llamada NO espera a que el
    // consumidor lento del primer stream termine de drenar — el préstamo del pool se
    // libera al terminar la GENERACIÓN (pre-F3A la segunda esperaba el drenaje entero).
    #[test]
    fn live_stream_slow_drain_releases_pool() {
        let Some(path) = test_gguf_path() else { return };
        let p = Arc::new(LocalGgufProvider::new(path, 16, LocalKnobs::default()));
        // Warmup: paga la carga para que los tiempos de abajo midan sólo generación.
        let mut warm = LLMRequest::new("reason");
        warm.data.insert("prompt".to_string(), "hi".to_string());
        let _ = p.call(&warm);

        let p1 = p.clone();
        let h = std::thread::spawn(move || {
            let mut req = LLMRequest::new("stream");
            req.data
                .insert("prompt".to_string(), "Count from one to ten in words.".to_string());
            let t0 = std::time::Instant::now();
            let _ = p1.call_stream(&req, &mut |_| {
                std::thread::sleep(std::time::Duration::from_millis(300)); // cliente lento
                true
            });
            t0.elapsed()
        });
        // Dar tiempo a que el stream 1 esté en curso, luego competir por la instancia.
        std::thread::sleep(std::time::Duration::from_millis(700));
        let mut req2 = LLMRequest::new("reason");
        req2.data
            .insert("prompt".to_string(), "Reply with exactly one word: pong".to_string());
        let t0 = std::time::Instant::now();
        let r2 = p.call(&req2);
        let fast = t0.elapsed();
        let slow_total = h.join().expect("hilo del stream lento");
        assert!(!r2.content.starts_with("[local error"), "error: {}", r2.content);
        assert!(
            fast.as_secs_f64() < slow_total.as_secs_f64() * 0.8,
            "la 2ª llamada no debía esperar el drenaje completo (fast {:?} vs slow {:?})",
            fast,
            slow_total
        );
    }

    // §4.6: call_step() con catálogo → ToolCall bien parseada; prompt trivial → Final.
    #[test]
    fn live_call_step_tool_and_final() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 128, LocalKnobs::default());
        let tools = vec![
            tool("get_weather", "Get the current weather for a city", &["city"]),
            tool("send_mail", "Send an email", &["to", "body"]),
        ];
        let mut req = LLMRequest::new("step").with_tools(tools.clone());
        req.data.insert(
            "prompt".to_string(),
            "Use the get_weather tool to find the weather in Madrid. You MUST call the tool.".to_string(),
        );
        let r = p.call_step(&req);
        assert!(r.tokens_used > 0, "tokens_used debe contar prompt + generados");
        match r.step {
            LlmStep::ToolCall { name, .. } => assert_eq!(name, "get_weather"),
            LlmStep::Final(t) => panic!("esperaba ToolCall, el modelo respondió: {}", t),
        }

        // Prompt trivial SIN relación con el catálogo (un 0.5B se distrae si el prompt
        // menciona cualquier cosa cercana a una tool).
        let mut req2 = LLMRequest::new("step").with_tools(tools);
        req2.data.insert("prompt".to_string(), "What is 2 plus 2? Reply with just the number.".to_string());
        let r2 = p.call_step(&req2);
        match r2.step {
            LlmStep::Final(t) => assert!(!t.is_empty()),
            LlmStep::ToolCall { name, .. } => panic!("no debía llamar tool, llamó: {}", name),
        }
    }
}

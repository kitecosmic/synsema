//! `decide`: decisiones tipadas con probabilidades calibradas, corriendo local.
//!
//! Es la puerta que sirve al `judge` de Synsema sin red, sin secreto y sin costo por token. El
//! contrato es el mismo que ya define `specs/system-one-judge.md`: se declara la forma de la
//! respuesta y el modelo la devuelve con una distribución de probabilidad encima.
//!
//! ## Cómo se resuelve el checkpoint
//!
//! Un checkpoint de Laya es un **directorio**, no un archivo: `model.safetensors`,
//! `rl_agent_config.json`, `encoder/config.json` y `tokenizer/`. Se acepta una ruta a ese
//! directorio, o un `org/repo` que **ya esté** en el cache de Hugging Face. Igual que con los GGUF
//! (§4), acá no se descarga nada: bajar 843 MB es una decisión del operador, no un efecto
//! secundario de correr un programa.
//!
//! ## Memoria
//!
//! El modelo se corre en `f32`, así que un checkpoint de 421M parámetros ocupa **~1,7 GB** de RAM
//! mientras está cargado. Se carga una vez por proceso y se comparte, igual que los GGUF.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use candle_core::{Device, Tensor};
use candle_transformers::models::modernbert;
use serde_json::Value;

use crate::arch_candle_laya::LayaModel;
use crate::laya::{self, AgentConfig, QType, Question};
use crate::store::StoreConfig;
use crate::tokenizer::HfTokenizer;

/// La respuesta a una pregunta.
#[derive(Clone, Debug)]
pub struct Answer {
    pub kind: QType,
    /// Confianza por entropía normalizada, en `[0, 1]`.
    pub confidence: f32,
    /// La distribución completa, etiqueta por etiqueta y en el orden declarado.
    pub probabilities: Vec<(String, f32)>,
    /// `choice`: la etiqueta ganadora.
    pub choice: Option<String>,
    /// `score`: el valor esperado sobre los niveles.
    pub score: Option<f32>,
    /// `noul`: P(verdadero). En Synsema se expone como `truth`.
    pub truth: Option<f32>,
}

/// El resultado de una llamada, con lo que hace falta para el metering y el audit.
#[derive(Clone, Debug)]
pub struct Decision {
    pub answers: Vec<(String, Answer)>,
    pub input_tokens: u64,
}

// =========================================================
// La sesión
// =========================================================

/// Qué implementación corre el modelo.
///
/// Las dos dan el mismo resultado (el oráculo de `arch_modernbert` lo verifica logit a logit
/// sobre el checkpoint real). Conviven porque el spec lo pide: **candle sigue siendo el default
/// hasta que el propio pase todos los goldens**, así que si algo sale mal quedamos como antes.
enum Backend {
    Candle(LayaModel),
    #[cfg(feature = "rust-backend")]
    Rust(crate::arch_modernbert::LayaRustModel),
}

impl Backend {
    fn score_markers(
        &self,
        ids: &[u32],
        markers: &[usize],
        qtype: usize,
    ) -> Result<Vec<f32>, String> {
        match self {
            Backend::Candle(m) => {
                m.score_markers(ids, markers, qtype).map_err(|e| format!("{}", e))
            }
            #[cfg(feature = "rust-backend")]
            Backend::Rust(m) => m.score_markers(ids, markers, qtype),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Backend::Candle(_) => "candle",
            #[cfg(feature = "rust-backend")]
            Backend::Rust(_) => "rust",
        }
    }
}

/// Un checkpoint de Laya cargado y listo.
pub struct LayaSession {
    model: Backend,
    tokenizer: HfTokenizer,
    agent: AgentConfig,
    path: PathBuf,
}

static LOADED: OnceLock<Mutex<HashMap<String, Arc<Result<LayaSession, String>>>>> = OnceLock::new();

fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Carga memoizada por spec, con la misma disciplina que los GGUF: una vez por proceso, el error
/// también se memoiza, y la carga corre bajo el lock para que dos llamadas concurrentes no la
/// dupliquen (son ~1,7 GB: duplicarla no es un detalle).
pub fn load(spec: &str, store: &StoreConfig) -> Arc<Result<LayaSession, String>> {
    let map = LOADED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = lock_unpoisoned(map);
    if let Some(a) = g.get(spec) {
        return a.clone();
    }
    let loaded = Arc::new(LayaSession::open(spec, store));
    g.insert(spec.to_string(), loaded.clone());
    loaded
}

impl LayaSession {
    fn open(spec: &str, store: &StoreConfig) -> Result<LayaSession, String> {
        let dir = resolve_checkpoint_dir(spec, store)?;

        let agent_raw = read_json(&dir.join("rl_agent_config.json"))?;
        let agent = AgentConfig::from_json(&agent_raw)?;
        let encoder_raw = read_json(&dir.join("encoder").join("config.json"))?;
        let encoder_config = encoder_config_from_json(&encoder_raw)?;

        let tokenizer = HfTokenizer::from_dir(&dir.join("tokenizer"))?;

        let weights_path = dir.join("model.safetensors");
        let model = load_backend(&weights_path, &encoder_raw, &encoder_config, &agent)?;

        Ok(LayaSession { model, tokenizer, agent, path: dir })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Qué implementación está corriendo: `candle` o `rust`. Va al nombre del provider, así que
    /// un log dice con qué motor se produjo cada decisión.
    pub fn backend(&self) -> &'static str {
        self.model.name()
    }

    /// Responde las preguntas sobre el estado dado.
    ///
    /// Las preguntas se corren **de a una**: `judge` suele traer pocas, y en CPU el padding al
    /// largo de la más grande cuesta más de lo que ahorra batchear.
    pub fn decide(
        &self,
        state: &Value,
        questions: &[(String, Question)],
    ) -> Result<Decision, String> {
        let mut answers = Vec::with_capacity(questions.len());
        let mut input_tokens = 0u64;

        for (qid, q) in questions {
            let seq = laya::build_sequence(
                &self.tokenizer,
                state,
                q,
                self.agent.max_len,
                self.agent.head_max_len,
            )?;
            let k = q.option_count();
            // Si un marcador quedó fuera del presupuesto, esa opción no se puntuó. Responder
            // igual sería inventar una distribución sobre opciones que el modelo nunca vio.
            if seq.markers.len() != k {
                return Err(format!(
                    "la pregunta '{}' tiene demasiadas opciones para el presupuesto de tokens \
                     ({} de {} entraron); acortá las descripciones o reducí las opciones",
                    qid,
                    seq.markers.len(),
                    k
                ));
            }
            input_tokens += seq.ids.len() as u64;

            let logits = self
                .model
                .score_markers(&seq.ids, &seq.markers, q.kind.index())
                .map_err(|e| format!("la pregunta '{}' falló en el modelo: {}", qid, e))?;
            if !logits.iter().all(|v| v.is_finite()) {
                return Err(format!("la pregunta '{}' produjo logits no finitos", qid));
            }

            let temperature = self.agent.temperature_for(q.kind, k);
            let p = laya::calibrated_probabilities(&logits, k, temperature);
            answers.push((qid.clone(), build_answer(q, &p, k)));
        }

        Ok(Decision { answers, input_tokens })
    }
}

fn build_answer(q: &Question, p: &[f32], k: usize) -> Answer {
    let labels = q.labels();
    let probabilities: Vec<(String, f32)> =
        labels.iter().zip(p.iter()).map(|(l, v)| (l.clone(), laya::round4(*v))).collect();

    let mut answer = Answer {
        kind: q.kind,
        confidence: laya::round4(laya::confidence_from_probs(p, k)),
        probabilities,
        choice: None,
        score: None,
        truth: None,
    };

    match q.kind {
        QType::Choice => {
            let best = p
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);
            answer.choice = labels.get(best).cloned();
        }
        QType::Score => {
            // Valor esperado sobre los niveles: un 0,5 entre "bajo" y "alto" es información que
            // el argmax tiraría.
            let expected: f32 = p.iter().enumerate().map(|(i, v)| i as f32 * v).sum();
            answer.score = Some(laya::round4(expected));
        }
        QType::Noul => {
            let t = p.get(1).copied().unwrap_or(0.0);
            answer.truth = Some(laya::round4(t));
            // Para una proposición, la confianza es qué tan lejos está del 50/50 — no la entropía
            // de la distribución, que acá diría lo mismo de otra forma pero peor.
            answer.confidence = laya::round4(t.max(1.0 - t));
        }
    }
    answer
}

// =========================================================
// Carga de archivos
// =========================================================

/// Elige e inicializa el backend.
///
/// `SYNSEMA_INFER_BACKEND=rust` usa el propio; cualquier otra cosa (o nada) usa candle, que es el
/// default mientras coexistan. Se lee acá y no en el crate de reglas porque **qué motor corre es
/// una decisión del operador**, igual que qué modelo.
fn load_backend(
    weights_path: &Path,
    encoder_raw: &Value,
    encoder_config: &modernbert::Config,
    agent: &AgentConfig,
) -> Result<Backend, String> {
    // El MISMO knob que el decoder, resuelto en el MISMO lugar: dos lecturas del entorno para
    // la misma pregunta se desincronizan sola una vez que una de las dos aprende a leer el `.env`.
    let want_rust = crate::want_rust_backend();

    #[cfg(feature = "rust-backend")]
    if want_rust {
        let weights = crate::safetensors::load(weights_path)?;
        let cfg = crate::arch_modernbert::EncoderConfig::from_json(encoder_raw)?;
        let model = crate::arch_modernbert::LayaRustModel::load(weights, cfg, agent)?;
        return Ok(Backend::Rust(model));
    }
    #[cfg(not(feature = "rust-backend"))]
    if want_rust {
        return Err(
            "SYNSEMA_INFER_BACKEND=rust requiere un binario compilado con --features rust-backend"
                .to_string(),
        );
    }
    let _ = encoder_raw;

    let weights = load_safetensors(weights_path)?;
    let model = LayaModel::load(weights, encoder_config, agent, &Device::Cpu)
        .map_err(|e| format!("no se pudieron cargar los pesos de Laya: {}", e))?;
    Ok(Backend::Candle(model))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("no se pudo leer {}: {}", path.display(), e))?;
    serde_json::from_str(&raw).map_err(|e| format!("{} no es JSON válido: {}", path.display(), e))
}

fn load_safetensors(path: &Path) -> Result<HashMap<String, Tensor>, String> {
    if !path.is_file() {
        return Err(format!("falta {}: no parece un checkpoint de Laya", path.display()));
    }
    candle_core::safetensors::load(path, &Device::Cpu)
        .map_err(|e| format!("no se pudo leer {}: {}", path.display(), e))
}

/// Arma el `Config` de ModernBERT desde el `config.json` del checkpoint.
///
/// No se deserializa directo: el config de Laya guarda los `rope_theta` **anidados** en
/// `rope_parameters.{full,sliding}_attention`, mientras que candle los espera como campos de
/// primer nivel. Traducirlo acá, explícito, es preferible a un `serde` con alias que después
/// nadie entiende.
pub(crate) fn encoder_config_from_json(v: &Value) -> Result<modernbert::Config, String> {
    let usize_of = |field: &str| -> Result<usize, String> {
        v.get(field)
            .and_then(|x| x.as_u64())
            .map(|n| n as usize)
            .ok_or_else(|| format!("el config del encoder no declara `{}`", field))
    };
    let model_type = v.get("model_type").and_then(|x| x.as_str()).unwrap_or("");
    if model_type != "modernbert" {
        return Err(format!(
            "encoder '{}' no soportado; Laya usa modernbert",
            if model_type.is_empty() { "(sin declarar)" } else { model_type }
        ));
    }
    let rope = |kind: &str, fallback: f64| -> f64 {
        v.get("rope_parameters")
            .and_then(|r| r.get(kind))
            .and_then(|r| r.get("rope_theta"))
            .and_then(|x| x.as_f64())
            .unwrap_or(fallback)
    };
    Ok(modernbert::Config {
        vocab_size: usize_of("vocab_size")?,
        hidden_size: usize_of("hidden_size")?,
        num_hidden_layers: usize_of("num_hidden_layers")?,
        num_attention_heads: usize_of("num_attention_heads")?,
        intermediate_size: usize_of("intermediate_size")?,
        max_position_embeddings: usize_of("max_position_embeddings")?,
        layer_norm_eps: v
            .get("layer_norm_eps")
            .or_else(|| v.get("norm_eps"))
            .and_then(|x| x.as_f64())
            .unwrap_or(1e-5),
        pad_token_id: v.get("pad_token_id").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        global_attn_every_n_layers: usize_of("global_attn_every_n_layers")?,
        global_rope_theta: rope("full_attention", 160_000.0),
        local_attention: usize_of("local_attention")?,
        local_rope_theta: rope("sliding_attention", 10_000.0),
        classifier_config: None,
    })
}

/// Encuentra el directorio del checkpoint: una ruta, o un `org/repo` ya cacheado de HF.
fn resolve_checkpoint_dir(spec: &str, store: &StoreConfig) -> Result<PathBuf, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("no se indicó ningún checkpoint".to_string());
    }
    let as_path = Path::new(spec);
    if as_path.is_dir() {
        return Ok(as_path.to_path_buf());
    }
    // Un `org/repo` de HF: se busca el snapshot ya bajado.
    if spec.contains('/') && !as_path.exists() {
        if let Some(hub) = &store.hf_hub_dir {
            let repo_dir = hub.join(format!("models--{}", spec.replace('/', "--")));
            let snapshots = repo_dir.join("snapshots");
            if let Some(found) = newest_snapshot_with_weights(&snapshots) {
                return Ok(found);
            }
            return Err(format!(
                "'{}' no está en el cache de Hugging Face ({}). Bajalo primero:\n  \
                 hf download {} --local-dir <dir>   y usá esa ruta",
                spec,
                repo_dir.display(),
                spec
            ));
        }
    }
    Err(format!(
        "no se encontró el checkpoint '{}': no es un directorio ni un repo cacheado de Hugging Face",
        spec
    ))
}

/// El snapshot más reciente que **de verdad** tenga los pesos: un snapshot a medio bajar existe
/// como directorio y daría un error mucho más confuso más adelante.
fn newest_snapshot_with_weights(snapshots: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in std::fs::read_dir(snapshots).ok()?.flatten() {
        let p = e.path();
        if !p.is_dir() || !p.join("model.safetensors").is_file() {
            continue;
        }
        let mtime =
            e.metadata().ok().and_then(|m| m.modified().ok()).unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
            best = Some((mtime, p));
        }
    }
    best.map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encoder_config_reads_nested_rope_thetas() {
        let cfg = encoder_config_from_json(&json!({
            "model_type": "modernbert",
            "vocab_size": 50368, "hidden_size": 1024, "num_hidden_layers": 28,
            "num_attention_heads": 16, "intermediate_size": 2624,
            "max_position_embeddings": 8192, "layer_norm_eps": 1e-5,
            "pad_token_id": 50283, "global_attn_every_n_layers": 3, "local_attention": 128,
            "rope_parameters": {
                "full_attention": {"rope_theta": 160000.0},
                "sliding_attention": {"rope_theta": 10000.0}
            }
        }))
        .unwrap();
        assert_eq!(cfg.global_rope_theta, 160_000.0);
        assert_eq!(cfg.local_rope_theta, 10_000.0);
        assert_eq!(cfg.num_hidden_layers, 28);
    }

    #[test]
    fn non_modernbert_encoder_is_rejected() {
        let err = encoder_config_from_json(&json!({"model_type": "bert"})).unwrap_err();
        assert!(err.contains("modernbert"), "{}", err);
    }

    #[test]
    fn missing_checkpoint_says_what_it_looked_for() {
        let err = resolve_checkpoint_dir("/no/existe/laya", &StoreConfig::default()).unwrap_err();
        assert!(err.contains("no se encontró"), "{}", err);
    }

    // -- armado de respuestas (sin modelo) --

    fn q(kind: QType, criteria: laya::Criteria) -> Question {
        Question { kind, instructions: "x".into(), criteria }
    }

    #[test]
    fn choice_answer_picks_the_argmax_with_its_label() {
        let question = q(
            QType::Choice,
            laya::Criteria::Labels(vec![
                ("billing".into(), None),
                ("technical".into(), None),
                ("sales".into(), None),
            ]),
        );
        let a = build_answer(&question, &[0.2, 0.7, 0.1], 3);
        assert_eq!(a.choice.as_deref(), Some("technical"));
        assert_eq!(a.probabilities.len(), 3);
        assert_eq!(a.probabilities[0].0, "billing");
        assert!(a.confidence > 0.0);
    }

    #[test]
    fn score_answer_is_the_expected_value_not_the_argmax() {
        let question =
            q(QType::Score, laya::Criteria::Levels(vec![json!("bajo"), json!("medio"), json!("alto")]));
        // Mitad en el nivel 0 y mitad en el 2: el esperado es 1, que no es ningún argmax.
        let a = build_answer(&question, &[0.5, 0.0, 0.5], 3);
        assert!((a.score.unwrap() - 1.0).abs() < 1e-4, "score {:?}", a.score);
    }

    #[test]
    fn truth_answer_reports_probability_and_distance_from_the_coin_flip() {
        let question =
            q(QType::Noul, laya::Criteria::Truth { when_false: None, when_true: None });
        let a = build_answer(&question, &[0.25, 0.75], 2);
        assert!((a.truth.unwrap() - 0.75).abs() < 1e-4);
        assert!((a.confidence - 0.75).abs() < 1e-4, "confianza {}", a.confidence);
        // Y simétrico: 0,25 de verdadero es igual de informativo que 0,75.
        let b = build_answer(&question, &[0.75, 0.25], 2);
        assert!((b.confidence - 0.75).abs() < 1e-4);
    }
    // -- paridad del armado de secuencia contra el upstream --

    /// **La prueba que importa para la paridad.** Si el armado de secuencia difiere aunque sea en
    /// un token, todos los marcadores se corren y el modelo puntúa otra cosa — sin que nada falle.
    ///
    /// Los valores de referencia se obtuvieron corriendo `build_sequence` del upstream (el
    /// `common.py` de Laya) con el tokenizer real del checkpoint, sobre el caso publicado en su
    /// README. Gateado por `SYNSEMA_TEST_LAYA=/ruta/al/checkpoint`: sin checkpoint se saltea, como
    /// los demás tests en vivo.
    #[test]
    fn live_sequence_matches_upstream_token_for_token() {
        let Ok(dir) = std::env::var("SYNSEMA_TEST_LAYA") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_LAYA=/ruta/al/checkpoint de Laya");
            return;
        };
        let tok = HfTokenizer::from_dir(&Path::new(&dir).join("tokenizer"))
            .expect("el checkpoint debe traer tokenizer/");

        let state = json!({
            "from": "user@acme.com",
            "subject": "Duplicate charge on invoice #4411",
            "body": "Hi, we were billed twice for March. Please refund the duplicate today or we will cancel our plan."
        });
        let question = Question {
            kind: QType::Choice,
            instructions: "Which department should handle this request?".to_string(),
            criteria: laya::Criteria::Labels(vec![
                ("billing".into(), Some(json!("invoices, payments, refunds"))),
                ("technical".into(), Some(json!("bugs, outages, system errors"))),
                ("sales".into(), Some(json!("pricing, new contracts"))),
                ("other".into(), Some(json!("everything else"))),
            ]),
        };

        let seq = laya::build_sequence(&tok, &state, &question, 512, 192).unwrap();

        assert_eq!(seq.ids.len(), 96, "largo de la secuencia");
        assert_eq!(seq.markers, vec![12, 22, 32, 39], "posición de los marcadores");
        assert_eq!(
            &seq.ids[..20],
            &[
                50281, 22122, 1953, 27, 6758, 7811, 943, 6016, 436, 2748, 32, 50282, 50284,
                33484, 27, 29838, 1271, 13, 10762, 13
            ],
            "los primeros 20 tokens"
        );
        assert_eq!(
            &seq.ids[seq.ids.len() - 8..],
            &[359, 588, 14002, 776, 2098, 449, 94, 50282],
            "los últimos 8 tokens"
        );
        // Y cada marcador cae en un [MASK], que es lo que el scorer puntúa.
        for &m in &seq.markers {
            assert_eq!(seq.ids[m], tok.specials.mask_id, "el marcador {} no es [MASK]", m);
        }
    }
}

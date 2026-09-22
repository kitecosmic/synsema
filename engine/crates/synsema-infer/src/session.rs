//! Carga, pool de instancias y generación. El corazón del provider local.
//!
//! Diseño (las decisiones importantes, en orden — conservadas del provider original):
//! - **Carga LAZY y memoizada, UNA por proceso**: el cableado del provider corre para TODOS los
//!   programas (y `serve` lo llama por intérprete), así que el modelo NO se carga al cablear
//!   sino en la primera op, y el resultado (ok O error) queda en un cache process-wide por path
//!   (`LOADED`). Un `run` que no usa LLM no paga nada; un path roto no se reintenta por llamada;
//!   `serve` carga una sola vez para todos sus intérpretes.
//! - **Aislamiento de KV cache**: cada llamada arranca con `clear_kv_cache()` sobre la instancia
//!   que toma del pool — dos llamadas (consecutivas o concurrentes) JAMÁS comparten ni heredan
//!   estado de generación. Ahora el trait lo exige (`arch.rs` §2.2), así que una arquitectura
//!   nueva no puede entrar sin cumplirlo.
//! - **Concurrencia por pool-semáforo**: `max_concurrent` (default 1) fija el máximo de
//!   instancias vivas. Con el default, requests simultáneos bajo `serve` se serializan (una
//!   instancia, cola FIFO por condvar). Subirlo crea instancias extra bajo demanda (re-lee el
//!   GGUF: RAM proporcional — opt-in consciente del usuario).
//! - **Una sola lectura del GGUF por carga**: el `GgufFile` de la pasada de metadata se reusa
//!   para construir los pesos.
//! - **Errores NUNCA panican**: todo el camino devuelve `Result`; quien lo convierte en
//!   `[local error: …]` es el adaptador del runtime.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

use crate::arch::{self, Model};
use crate::gguf::GgufFile;
use crate::knobs::LocalKnobs;
use crate::store::{self, ModelOrigin, StoreConfig};
use crate::sampling::Sampler;
use crate::tensor::Tensor;
use crate::tokenizer::{ChatTemplate, Tokenizer};

// =========================================================
// Cache process-wide de modelos cargados
// =========================================================

static LOADED: OnceLock<Mutex<HashMap<String, Arc<Result<Session, String>>>>> = OnceLock::new();

/// Toma un lock ignorando poison (el camino de inferencia no panica; si un test paniqueó con
/// el lock tomado, el estado sigue siendo usable).
fn lock_unpoisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Carga memoizada **por spec**. La carga corre BAJO el lock del map: llamadas concurrentes a la
/// primera op esperan la carga en curso en vez de duplicarla.
///
/// Se memoiza por el spec y no por el path resuelto a propósito: es lo que el operador escribió,
/// y si dos specs distintos apuntan al mismo archivo, cada uno conserva su propia procedencia
/// (un blob de Ollama y una ruta directa al mismo blob no son lo mismo para el audit).
pub fn load(spec: &str, store: &StoreConfig, max_concurrent: usize) -> Arc<Result<Session, String>> {
    let map = LOADED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = lock_unpoisoned(map);
    if let Some(a) = g.get(spec) {
        return a.clone();
    }
    let loaded = Arc::new(Session::open(spec, store, max_concurrent));
    g.insert(spec.to_string(), loaded.clone());
    loaded
}

// =========================================================
// La sesión: metadata inmutable compartida + pool de instancias
// =========================================================

/// Un modelo cargado y listo: tokenizer + template + metadata inmutables compartidos, y el pool
/// de instancias (los pesos con su estado mutable por instancia).
pub struct Session {
    path: String,
    arch: String,
    /// De dónde salió el archivo. Va al audit: saber qué corrió incluye saber de dónde vino.
    origin: ModelOrigin,
    /// SHA-256 de los pesos, **si el origen lo provee sin costo**. Ollama lo regala en el nombre
    /// del blob (es content-addressed); una ruta suelta o un snapshot de HF no, y no se calcula
    /// acá: hashear 4 GB en cada primera carga sería un impuesto silencioso sobre el arranque.
    digest: Option<String>,
    tokenizer: Tokenizer,
    template: ChatTemplate,
    /// Tokens que terminan la generación (eos del GGUF + el de cierre del template).
    eos_ids: Vec<u32>,
    /// Contexto máximo declarado por el GGUF.
    model_ctx: usize,
    pool: ModelPool,
}

/// Los dos backends detrás de una interfaz común: **entra una lista de tokens, salen logits**.
///
/// La frontera es `Vec<f32>` a propósito: ni el sampler ni la generación tienen que saber de
/// tensores de nadie, y agregar un backend no toca ninguno de los dos.
enum Decoder {
    Candle(Box<dyn Model>),
    #[cfg(feature = "rust-backend")]
    Rust(crate::archrun::ArchModel),
}

impl Decoder {
    /// Procesa `ids` desde la posición `pos` y devuelve los logits del **último** token.
    fn forward(&mut self, ids: &[u32], pos: usize) -> Result<Vec<f32>, String> {
        match self {
            Decoder::Candle(m) => {
                let input = Tensor::from_token_ids(ids)?;
                let logits = m.forward(&input, pos)?;
                // candle devuelve `[1, vocab]` para un token y `[1, n, vocab]` para varios; en
                // ambos casos lo que sirve es la última fila.
                let flat = logits.squeeze_batch()?.to_f32_vec()?;
                Ok(flat)
            }
            #[cfg(feature = "rust-backend")]
            // El nuestro lleva la posición en su propio cache: no hace falta pasársela.
            Decoder::Rust(m) => m.forward(ids),
        }
    }

    fn clear_kv_cache(&mut self) {
        match self {
            Decoder::Candle(m) => m.clear_kv_cache(),
            #[cfg(feature = "rust-backend")]
            Decoder::Rust(m) => m.clear_kv_cache(),
        }
    }

    fn backend_name(&self) -> &'static str {
        match self {
            Decoder::Candle(_) => "candle",
            #[cfg(feature = "rust-backend")]
            Decoder::Rust(_) => "rust",
        }
    }
}

/// Pool-semáforo de instancias. Con `max = 1` equivale a un mutex con cola justa; con más, crea
/// instancias bajo demanda (cada una re-lee el GGUF → RAM proporcional, opt-in documentado).
struct ModelPool {
    inner: Mutex<PoolInner>,
    cv: Condvar,
}

struct PoolInner {
    idle: Vec<Decoder>,
    created: usize,
    max: usize,
}

impl Session {
    /// Carga completa: metadata + tokenizer + template + primera instancia, con UNA sola
    /// lectura del GGUF.
    fn open(spec: &str, store: &StoreConfig, max_concurrent: usize) -> Result<Session, String> {
        let resolved = store::resolve(spec, store)?;
        let path = resolved
            .path
            .to_str()
            .ok_or_else(|| format!("la ruta del modelo no es texto válido: {:?}", resolved.path))?
            .to_string();
        let path = path.as_str();
        let gguf = GgufFile::open(path)?;
        let arch_name = gguf.architecture()?;

        // Fallar acá y no después de construir el tokenizer: un GGUF de una arquitectura que no
        // sabemos correr no debería costar el parseo del vocabulario entero.
        //
        // **Qué se puede correr depende del backend.** El propio soporta arquitecturas que candle
        // no expone con reset de KV —gemma3, sin ir más lejos— así que preguntarle a la lista
        // equivocada rechazaría modelos que sí funcionan.
        if !architecture_supported(&arch_name) {
            return Err(unsupported_architecture(&arch_name));
        }

        let model_ctx = gguf.context_length(&arch_name);
        let tokenizer = Tokenizer::from_gguf(&gguf)?;
        let template = ChatTemplate::detect(&gguf, &tokenizer);

        // EOS: el declarado por el GGUF + el token de cierre del template si existe en el vocab
        // (los GGUF de llama3/qwen a veces declaran sólo uno de los dos).
        let mut eos_ids: Vec<u32> = Vec::new();
        if let Some(id) = gguf.meta_u32("tokenizer.ggml.eos_token_id") {
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
            return Err(
                "GGUF sin `tokenizer.ggml.eos_token_id` ni token de cierre conocido".to_string()
            );
        }

        // El token de comienzo lo resuelve el tokenizer, que ya leyó esta metadata.

        // Consume el GGUF: la primera instancia sale de la misma lectura.
        let first = build_decoder(path, &arch_name, gguf)?;

        Ok(Session {
            path: path.to_string(),
            arch: arch_name,
            origin: resolved.origin,
            digest: resolved.digest,
            tokenizer,
            template,
            eos_ids,
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

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn architecture(&self) -> &str {
        &self.arch
    }

    /// Qué implementación corre: `candle` o `rust`. Va al nombre del provider, así que un log dice
    /// con qué motor se generó cada respuesta.
    pub fn backend(&self) -> &'static str {
        let g = lock_unpoisoned(&self.pool.inner);
        g.idle.first().map(|d| d.backend_name()).unwrap_or("en uso")
    }

    /// Contexto máximo declarado por el GGUF.
    pub fn model_ctx(&self) -> usize {
        self.model_ctx
    }

    /// De dónde salió el archivo.
    pub fn origin(&self) -> &ModelOrigin {
        &self.origin
    }

    /// SHA-256 de los pesos si el origen lo provee sin costo. Ver el campo.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    /// Una línea de procedencia para el audit: qué archivo, de dónde y con qué hash.
    pub fn provenance(&self) -> String {
        match &self.digest {
            Some(sha) => format!("{} ({}, sha256:{})", self.path, self.origin.label(), sha),
            None => format!("{} ({})", self.path, self.origin.label()),
        }
    }

    /// Toma una instancia del pool (creándola o esperando según `max`), corre `f` y la devuelve
    /// SIEMPRE (también si `f` falla). El aislamiento de KV lo garantiza `generate` (clear al
    /// inicio); acá sólo va la disciplina de préstamo.
    fn with_model<T>(
        &self,
        f: impl FnOnce(&mut Decoder) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut m = self.acquire()?;
        let r = f(&mut m);
        let mut g = lock_unpoisoned(&self.pool.inner);
        g.idle.push(m);
        drop(g);
        self.pool.cv.notify_one();
        r
    }

    fn acquire(&self) -> Result<Decoder, String> {
        let mut g = lock_unpoisoned(&self.pool.inner);
        loop {
            if let Some(m) = g.idle.pop() {
                return Ok(m);
            }
            if g.created < g.max {
                g.created += 1;
                drop(g);
                // Crecer el pool re-lee el GGUF: es el costo documentado de max_concurrent > 1.
                let built = GgufFile::open(&self.path)
                    .and_then(|gguf| build_decoder(&self.path, &self.arch, gguf));
                match built {
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

    /// Genera texto tomando una instancia del pool. Ver `generate` para la semántica del sink.
    pub fn generate(
        &self,
        user_text: &str,
        knobs: &LocalKnobs,
        max_tokens: u64,
        sink: Option<&mut dyn FnMut(&str) -> bool>,
    ) -> Result<(String, u64), String> {
        self.with_model(|m| generate(self, m, user_text, knobs, max_tokens, sink))
    }
}

/// Las arquitecturas que el backend activo sabe correr.
///
/// Para el backend propio la respuesta **no está escrita en el binario**: es la que da el registro
/// de definiciones, que incluye el directorio del operador. Por eso esta función existe en vez de
/// una constante — desde I5, qué se puede correr cambia sin recompilar.
fn architecture_supported(arch: &str) -> bool {
    #[cfg(feature = "rust-backend")]
    if crate::want_rust_backend() {
        return crate::arch_registry::Registry::shared().find(arch).is_some();
    }
    arch::SUPPORTED.contains(&arch)
}

/// El error, con la lista del backend que de verdad va a correr.
fn unsupported_architecture(arch: &str) -> String {
    #[cfg(feature = "rust-backend")]
    if crate::want_rust_backend() {
        // El registro arma el mensaje: sabe qué hay, qué definiciones del directorio fallaron y
        // cómo sumar una. Duplicar eso acá sería que las dos listas se separen con el tiempo.
        return crate::arch_registry::Registry::shared().unknown(arch);
    }
    // Vale la pena decir que el otro backend quizá sí puede: es la diferencia entre "no se puede"
    // y "probá con este knob".
    #[cfg(feature = "rust-backend")]
    if crate::arch_registry::Registry::shared().find(arch).is_some() {
        return format!(
            "{}
  El backend propio sí la soporta: probá con SYNSEMA_INFER_BACKEND=rust",
            arch::unsupported(arch)
        );
    }
    arch::unsupported(arch)
}

/// Construye el decoder con el backend que pidió el operador.
///
/// **El camino propio re-lee el archivo**: nuestro cargador trabaja sobre los bytes crudos, no
/// sobre el handle que ya abrió el otro backend. Desde I4-e los pesos grandes se quedan
/// cuantizados y desde I4-d el archivo se mapea en vez de copiarse, así que el modelo ocupa
/// aproximadamente lo que ocupa el `.gguf` — la mitad que el otro backend, medido.
///
/// Y desde I5 la **arquitectura sale de una definición**, no de un `match` compilado: el registro
/// busca `general.architecture` entre las que trae el binario y las que puso el operador.
fn build_decoder(path: &str, arch_name: &str, gguf: GgufFile) -> Result<Decoder, String> {
    #[cfg(feature = "rust-backend")]
    if crate::want_rust_backend() {
        // Soltar el handle del otro backend antes de mapear el archivo.
        drop(gguf);
        // MAPEADO, no leído: el modelo ocupa lo que ocupa el archivo, y el sistema operativo
        // pagina lo que haga falta. Es lo que permite correr un modelo más grande que la RAM.
        let bytes = std::sync::Arc::new(crate::mapped::ModelBytes::map(std::path::Path::new(path))?);
        let header = crate::gguf_rust::parse_header(bytes.as_slice())?;
        let registry = crate::arch_registry::Registry::shared();
        let def = registry
            .find(arch_name)
            .ok_or_else(|| registry.unknown(arch_name))?
            .clone();
        let model = crate::archrun::ArchModel::load(def, &header, &bytes)?;
        return Ok(Decoder::Rust(model));
    }
    let _ = path;
    Ok(Decoder::Candle(arch::build(arch_name, gguf)?))
}

// =========================================================
// Generación
// =========================================================

/// Genera texto con una instancia prestada del pool. SIEMPRE arranca con `clear_kv_cache()` →
/// una llamada no puede ver tokens de otra. Devuelve `(texto, tokens = prompt + generados)`.
///
/// `sink`: si está, cada fragmento se emite a medida que se genera, con **detokenización
/// incremental correcta**: JAMÁS token-por-token suelto (BPE byte-level y SPM parten chars
/// multi-byte y pierden espacios) — se decodifica el ACUMULADO y se emite el diff, reteniendo
/// el final si termina en char parcial (`�`) hasta que se complete. Garantía verificada por
/// test: sin early-stop, la concatenación de los chunks == el retorno, byte-exacto (por eso el
/// camino con sink NO trimmea). Si el sink devuelve `false` (p.ej. cliente SSE desconectado),
/// la generación CORTA y se devuelve lo generado hasta ahí — el aislamiento lo garantiza el
/// `clear_kv_cache` de la PRÓXIMA llamada.
fn generate(
    session: &Session,
    model: &mut Decoder,
    user_text: &str,
    knobs: &LocalKnobs,
    max_tokens: u64,
    mut sink: Option<&mut dyn FnMut(&str) -> bool>,
) -> Result<(String, u64), String> {
    let prompt = session.template.apply(user_text);
    // `encode_prompt` —y no `encode`— pone el token de comienzo si el modelo lo pide. Vive en el
    // tokenizer y en ningún otro lado: estuvo un tiempo también acá, y dos copias de una regla es
    // el camino más corto a que digan cosas distintas.
    let ids = session.tokenizer.encode_prompt(&prompt)?;

    let ctx = knobs.ctx.min(session.model_ctx).max(16);
    if ids.len() >= ctx {
        return Err(format!(
            "el prompt ({} tokens) excede el contexto disponible ({} tokens)",
            ids.len(),
            ctx
        ));
    }
    let budget = (max_tokens as usize).min(ctx - ids.len());

    model.clear_kv_cache();
    let mut sampler = Sampler::new(knobs.temperature);

    // Prefill: todo el prompt en una pasada (posición 0); después token a token.
    let logits = model.forward(&ids, 0)?;
    let mut next = sampler.sample(&logits)?;

    let mut generated: Vec<u32> = Vec::new();
    let mut pos = ids.len();
    // Streaming: bytes del texto decodificado ya emitidos (offset sobre el decode ACUMULADO —
    // el prefijo ya decodificado es estable, sólo se appendea).
    let mut emitted = 0usize;
    let mut stopped = false;
    while generated.len() < budget {
        if session.eos_ids.contains(&next) {
            break;
        }
        generated.push(next);
        if let Some(s) = sink.as_deref_mut() {
            let so_far = session.tokenizer.decode(&generated)?;
            // Emitir el diff sólo cuando creció y NO termina en char parcial (byte partido de un
            // multi-byte → `�`); si `emitted` no cae en un límite de char (defensivo: el decoder
            // reescribió el final), retener y reintentar después.
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
        let logits = model.forward(&[next], pos)?;
        next = sampler.sample(&logits)?;
        pos += 1;
    }

    let text = session.tokenizer.decode(&generated)?;
    let tokens = (ids.len() + generated.len()) as u64;
    if let Some(s) = sink.as_deref_mut() {
        // Flush del residuo retenido (char parcial al final, o el último token antes del EOS) —
        // así la concatenación de chunks == el retorno, byte-exacto. Tras un early-stop no se
        // emite más (el cliente ya no está); el retorno igual lleva todo lo generado. El camino
        // streaming NO trimmea (rompería la igualdad).
        if !stopped && text.len() > emitted {
            if let Some(rest) = text.get(emitted..) {
                let _ = s(rest);
            }
        }
        return Ok((text, tokens));
    }
    Ok((text.trim().to_string(), tokens))
}

/// Sonda de diagnóstico: qué entra al modelo y qué predice.
///
/// No afirma nada — imprime. Existe porque mirar el texto generado no alcanza para saber si lo que
/// está mal es el prompt, el vocabulario o la aritmética, y adivinar entre esas tres cuesta horas.
///
/// `SYNSEMA_PROBE_MODEL=gemma3:270m cargo test -p synsema-infer --release probe -- --nocapture`
#[cfg(all(test, feature = "rust-backend"))]
mod probe {
    use super::*;

    #[test]
    fn what_goes_in_and_what_comes_out() {
        let Ok(spec) = std::env::var("SYNSEMA_PROBE_MODEL") else {
            eprintln!("[skip] seteá SYNSEMA_PROBE_MODEL=<modelo>");
            return;
        };
        let store = StoreConfig::from_env();
        let resolved = store::resolve(&spec, &store).expect("resolver el modelo");
        let path = resolved.path.to_str().expect("ruta").to_string();
        let gguf = GgufFile::open(&path).expect("abrir gguf");
        let arch = gguf.architecture().expect("arquitectura");
        let tok = Tokenizer::from_gguf(&gguf).expect("tokenizer");
        let tpl = ChatTemplate::detect(&gguf, &tok);
        let bos = gguf.meta_u32("tokenizer.ggml.bos_token_id");
        let add_bos = gguf.meta_bool("tokenizer.ggml.add_bos_token");
        let eos = gguf.meta_u32("tokenizer.ggml.eos_token_id");

        let user = std::env::var("SYNSEMA_PROBE_PROMPT")
            .unwrap_or_else(|_| "The capital of France is".to_string());
        let raw = std::env::var("SYNSEMA_PROBE_RAW").is_ok();
        let prompt = if raw { user.clone() } else { tpl.apply(&user) };

        let mut ids = tok.encode(&prompt).expect("encode");
        if add_bos.unwrap_or(false) {
            if let Some(b) = bos {
                if ids.first() != Some(&b) {
                    ids.insert(0, b);
                }
            }
        }

        eprintln!("--- {} ({}) ---", spec, arch);
        eprintln!("template   {:?}{}", tpl, if raw { "  (SALTEADO: modo raw)" } else { "" });
        eprintln!("bos={:?} add_bos={:?} eos={:?}", bos, add_bos, eos);
        eprintln!("prompt     {:?}", prompt);
        eprintln!("ids ({}):", ids.len());
        for id in &ids {
            eprintln!("   {:>7}  {:?}", id, tok.decode(&[*id]).unwrap_or_default());
        }

        let mut dec = build_decoder(&path, &arch, gguf).expect("decoder");
        dec.clear_kv_cache();
        let logits = dec.forward(&ids, 0).expect("forward");
        let mut order: Vec<usize> = (0..logits.len()).collect();
        order.sort_by(|a, b| logits[*b].partial_cmp(&logits[*a]).unwrap());
        eprintln!("top-8 del próximo token:");
        for i in order.iter().take(8) {
            eprintln!(
                "   {:>7}  {:9.4}  {:?}",
                i,
                logits[*i],
                tok.decode(&[*i as u32]).unwrap_or_default()
            );
        }

        // Y doce pasos codiciosos, para ver si se va por la banquina enseguida o de a poco.
        let mut out = Vec::new();
        let mut next = order[0] as u32;
        let mut pos = ids.len();
        for _ in 0..12 {
            out.push(next);
            let l = dec.forward(&[next], pos).expect("decode");
            pos += 1;
            next = l
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(i, _)| i as u32)
                .unwrap();
        }
        eprintln!("greedy ids: {:?}", out);
        eprintln!("greedy txt: {:?}", tok.decode(&out).unwrap_or_default());
    }
}

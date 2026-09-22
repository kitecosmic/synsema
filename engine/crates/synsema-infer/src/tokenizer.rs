//! Tokenización desde la metadata del GGUF, sin sidecar `tokenizer.json`.
//!
//! Dos familias, y **una sola de las dos se delega**:
//!
//! - `"gpt2"` (qwen, llama 3, …) → BPE byte-level. Se arma el JSON equivalente a un
//!   `tokenizer.json` desde `tokens` + `merges` y lo resuelve la crate `tokenizers`, que acá hace
//!   exactamente lo que corresponde. Verificado contra el modelo real.
//! - `"llama"` (SentencePiece: gemma, llama 1 y 2, mistral) → **[`crate::spm`], escrito por
//!   nosotros**. Antes esto también se delegaba, mapeándolo a un `Unigram`, y **estaba mal**: los
//!   GGUF de Gemma guardan los scores como rangos y no como log-probabilidades, así que el Viterbi
//!   del Unigram partía `▁The` en `▁T`+`he`. El módulo `spm` explica el caso con números.
//!
//! - **Los tokens de control (`token_type == 3`) y user-defined (`== 4`)** se reconocen
//!   literalmente antes de segmentar, para que los especiales del chat template den UN token.
//! - **Aproximación que queda**: en la familia BPE el pre-tokenizer es el ByteLevel estándar, no el
//!   exacto por familia de llama.cpp. Alcanza para los modelos que corremos, y está dicho acá para
//!   que nadie lo descubra como sorpresa.
//! - **El chat template está hardcodeado por familia**, detectado desde
//!   `tokenizer.chat_template` (que se olfatea, JAMÁS se ejecuta: es jinja de un archivo ajeno)
//!   o desde el vocabulario. Sin motor de plantillas.

use serde_json::{json, Map, Value};

use crate::gguf::GgufFile;

/// El tokenizer de la casa. Envuelve el de HF para que el resto del crate no dependa de su API:
/// cuando la tokenización sea nuestra, cambia este archivo y nada más.
pub struct Tokenizer {
    inner: Inner,
    /// El token de comienzo, **si el GGUF dice que hay que ponerlo**
    /// (`tokenizer.ggml.add_bos_token`). `None` cuando el modelo no lo quiere.
    bos: Option<u32>,
}

enum Inner {
    /// BPE byte-level, resuelto por la crate `tokenizers`.
    Bpe(Box<tokenizers::Tokenizer>),
    /// SentencePiece, nuestro.
    Spm(Box<crate::spm::Spm>),
}

impl Tokenizer {
    /// Tokeniza **tal cual**, sin agregar nada.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>, String> {
        match &self.inner {
            Inner::Bpe(t) => t
                .encode(text, false)
                .map(|e| e.get_ids().to_vec())
                .map_err(|e| format!("tokenización: {}", e)),
            Inner::Spm(s) => Ok(s.encode(text)),
        }
    }

    /// Tokeniza un prompt completo, poniendo el token de comienzo si el modelo lo pide.
    ///
    /// **No es cosmético.** Gemma declara `add_bos_token = 1`, y sin ese token responde texto
    /// degradado —palabras sueltas, mayúsculas raras— en vez de fallar. Qwen declara `0`, y por eso
    /// nunca lo notamos: el modelo con el que probábamos no lo necesitaba.
    ///
    /// Lo decide **la metadata del GGUF**, no una lista de modelos nuestra. Un modelo que mañana
    /// pida BOS lo va a tener sin que nadie toque este archivo.
    pub fn encode_prompt(&self, text: &str) -> Result<Vec<u32>, String> {
        let mut ids = self.encode(text)?;
        if let Some(bos) = self.bos {
            // Si el texto ya empieza con él —porque el template lo escribió— no se duplica.
            if ids.first() != Some(&bos) {
                ids.insert(0, bos);
            }
        }
        Ok(ids)
    }

    /// El token de comienzo que este modelo pide, si pide alguno. Para diagnóstico.
    pub fn bos(&self) -> Option<u32> {
        self.bos
    }

    pub fn decode(&self, ids: &[u32]) -> Result<String, String> {
        match &self.inner {
            Inner::Bpe(t) => t.decode(ids, true).map_err(|e| format!("detokenización: {}", e)),
            Inner::Spm(s) => Ok(s.decode(ids, true)),
        }
    }

    pub fn token_to_id(&self, token: &str) -> Option<u32> {
        match &self.inner {
            Inner::Bpe(t) => t.token_to_id(token),
            Inner::Spm(s) => s.token_to_id(token),
        }
    }

    /// Qué familia resolvió este vocabulario. Va al diagnóstico.
    pub fn family(&self) -> &'static str {
        match &self.inner {
            Inner::Bpe(_) => "bpe",
            Inner::Spm(_) => "spm",
        }
    }

    /// Reconstruye el tokenizer desde la metadata. Ver el diseño de arriba.
    pub fn from_gguf(gguf: &GgufFile) -> Result<Self, String> {
        let kind = gguf
            .meta_string("tokenizer.ggml.model")
            .ok_or_else(|| "GGUF sin `tokenizer.ggml.model` en la metadata".to_string())?;
        let tokens = gguf
            .meta_str_vec("tokenizer.ggml.tokens")
            .ok_or_else(|| "GGUF sin `tokenizer.ggml.tokens` en la metadata".to_string())?;
        let token_type = gguf.meta_i64_vec("tokenizer.ggml.token_type");

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

        let inner = match kind.as_str() {
            "gpt2" => {
                let json = gpt2_json(gguf, &tokens, added)?;
                let t = serde_json::from_value::<tokenizers::Tokenizer>(json).map_err(|e| {
                    format!("no se pudo reconstruir el tokenizer desde la metadata: {}", e)
                })?;
                Inner::Bpe(Box::new(t))
            }
            "llama" => {
                let scores = gguf.meta_f32_vec("tokenizer.ggml.scores").ok_or_else(|| {
                    "GGUF con vocab llama/SPM sin `tokenizer.ggml.scores`".to_string()
                })?;
                let types = token_type.clone().ok_or_else(|| {
                    "GGUF con vocab llama/SPM sin `tokenizer.ggml.token_type`".to_string()
                })?;
                let unk = gguf.meta_u32("tokenizer.ggml.unknown_token_id").unwrap_or(0);
                // SentencePiece agrega un espacio adelante salvo que el modelo diga que no.
                let prefix = gguf.meta_bool("tokenizer.ggml.add_space_prefix").unwrap_or(true);
                Inner::Spm(Box::new(crate::spm::Spm::new(tokens, scores, types, unk, prefix)?))
            }
            other => {
                return Err(format!(
                    "vocabulario '{}' no soportado por el provider local (soportados: gpt2, llama)",
                    other
                ))
            }
        };
        // Si el GGUF no lo declara, el default es el de la familia: los vocabularios SPM esperan
        // el token de comienzo y los BPE no. Es el mismo criterio de la referencia.
        let wants_bos = gguf
            .meta_bool("tokenizer.ggml.add_bos_token")
            .unwrap_or(kind == "llama");
        let bos = if wants_bos {
            gguf.meta_u32("tokenizer.ggml.bos_token_id")
        } else {
            None
        };
        Ok(Tokenizer { inner, bos })
    }
}

fn gpt2_json(gguf: &GgufFile, tokens: &[String], added: Vec<Value>) -> Result<Value, String> {
    let merges_raw = gguf
        .meta_str_vec("tokenizer.ggml.merges")
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
    Ok(json!({
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
    }))
}

// =========================================================
// Chat template (hardcodeado por familia — sin jinja)
// =========================================================

/// Formato de conversación de la familia del modelo. `Plain` = modelo base sin formato instruct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatTemplate {
    ChatMl,
    Llama3,
    Mistral,
    /// Gemma 2 y 3: turnos delimitados por `<start_of_turn>` / `<end_of_turn>`.
    Gemma,
    Plain,
}

impl ChatTemplate {
    pub fn apply(&self, user: &str) -> String {
        match self {
            ChatTemplate::ChatMl => {
                format!("<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n", user)
            }
            ChatTemplate::Llama3 => format!(
                "<|start_header_id|>user<|end_header_id|>\n\n{}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
                user
            ),
            ChatTemplate::Mistral => format!("[INST] {} [/INST]", user),
            // El `<bos>` NO va acá: lo pone `encode_prompt` desde `add_bos_token`, que es donde
            // vale para todos los modelos. La plantilla de Gemma lo lleva en su jinja, y ponerlo
            // en los dos lados lo duplicaría.
            ChatTemplate::Gemma => {
                format!("<start_of_turn>user\n{}<end_of_turn>\n<start_of_turn>model\n", user)
            }
            ChatTemplate::Plain => format!("{}\n", user),
        }
    }

    /// Tokens de cierre propios del template (se suman a los EOS del GGUF si existen).
    pub fn stop_tokens(&self) -> &'static [&'static str] {
        match self {
            ChatTemplate::ChatMl => &["<|im_end|>"],
            ChatTemplate::Llama3 => &["<|eot_id|>", "<|end_of_text|>"],
            ChatTemplate::Mistral => &["</s>"],
            ChatTemplate::Gemma => &["<end_of_turn>"],
            ChatTemplate::Plain => &[],
        }
    }

    /// Detecta la familia desde `tokenizer.chat_template` (que sólo se olfatea) o, si falta,
    /// desde el vocabulario.
    pub fn detect(gguf: &GgufFile, tokenizer: &Tokenizer) -> Self {
        if let Some(tpl) = gguf.meta_string("tokenizer.chat_template") {
            if tpl.contains("<|im_start|>") {
                return ChatTemplate::ChatMl;
            }
            if tpl.contains("<|start_header_id|>") {
                return ChatTemplate::Llama3;
            }
            if tpl.contains("[INST]") {
                return ChatTemplate::Mistral;
            }
            if tpl.contains("<start_of_turn>") {
                return ChatTemplate::Gemma;
            }
        }
        if tokenizer.token_to_id("<|im_start|>").is_some() {
            return ChatTemplate::ChatMl;
        }
        if tokenizer.token_to_id("<|start_header_id|>").is_some() {
            return ChatTemplate::Llama3;
        }
        if tokenizer.token_to_id("<start_of_turn>").is_some() {
            return ChatTemplate::Gemma;
        }
        ChatTemplate::Plain
    }
}

// =========================================================
// Tokenizer de un checkpoint HF (Laya) — con sus tokens especiales
// =========================================================

/// Los ids que el armado de secuencias necesita. Se resuelven **una vez, al cargar**: pedirlos por
/// token en cada llamada sería buscar en el vocabulario miles de veces por pregunta.
#[derive(Clone, Debug)]
pub struct SpecialTokens {
    pub cls_id: u32,
    pub sep_id: u32,
    pub mask_id: u32,
    pub pad_id: u32,
    /// El texto de la máscara, para poder borrarlo de la entrada del usuario.
    pub mask_token: String,
}

/// Un tokenizer de checkpoint HF: `tokenizer.json` más los tokens especiales de
/// `tokenizer_config.json`. Implementa [`crate::laya::SeqTokenizer`], así que las reglas puras de
/// armado de secuencia funcionan con él sin conocerlo.
pub struct HfTokenizer {
    inner: tokenizers::Tokenizer,
    pub specials: SpecialTokens,
}

impl HfTokenizer {
    /// Carga desde el directorio `tokenizer/` de un checkpoint.
    ///
    /// Falla si falta cualquiera de los cuatro tokens especiales: sin ellos la secuencia se arma
    /// mal y el modelo responde **igual**, sólo que mal. Es exactamente el tipo de error que no se
    /// puede detectar después.
    pub fn from_dir(dir: &std::path::Path) -> Result<Self, String> {
        let tok_path = dir.join("tokenizer.json");
        let inner = tokenizers::Tokenizer::from_file(&tok_path)
            .map_err(|e| format!("no se pudo leer {}: {}", tok_path.display(), e))?;

        let cfg_path = dir.join("tokenizer_config.json");
        let raw = std::fs::read_to_string(&cfg_path)
            .map_err(|e| format!("no se pudo leer {}: {}", cfg_path.display(), e))?;
        let cfg: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| format!("{} no es JSON válido: {}", cfg_path.display(), e))?;

        let text_of = |field: &str| -> Result<String, String> {
            // Puede venir como string o como objeto `{"content": "[CLS]", …}`.
            let v = cfg.get(field).ok_or_else(|| format!("el tokenizer no declara `{}`", field))?;
            let s = match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Object(o) => {
                    o.get("content").and_then(|c| c.as_str()).map(|c| c.to_string())
                }
                _ => None,
            };
            s.ok_or_else(|| format!("`{}` del tokenizer no es un token legible", field))
        };
        let id_of = |field: &str, token: &str| -> Result<u32, String> {
            inner
                .token_to_id(token)
                .ok_or_else(|| format!("`{}` ({}) no está en el vocabulario", field, token))
        };

        let cls = text_of("cls_token")?;
        let sep = text_of("sep_token")?;
        let mask = text_of("mask_token")?;
        let pad = text_of("pad_token")?;
        let specials = SpecialTokens {
            cls_id: id_of("cls_token", &cls)?,
            sep_id: id_of("sep_token", &sep)?,
            mask_id: id_of("mask_token", &mask)?,
            pad_id: id_of("pad_token", &pad)?,
            mask_token: mask,
        };
        Ok(HfTokenizer { inner, specials })
    }
}

impl crate::laya::SeqTokenizer for HfTokenizer {
    /// Sin tokens especiales automáticos: el `[CLS]` y los `[SEP]` los pone el armado, en las
    /// posiciones exactas que el modelo espera.
    fn encode_plain(&self, text: &str) -> Result<Vec<u32>, String> {
        self.inner
            .encode(text, false)
            .map(|e| e.get_ids().to_vec())
            .map_err(|e| format!("tokenización: {}", e))
    }
    fn cls_id(&self) -> u32 {
        self.specials.cls_id
    }
    fn sep_id(&self) -> u32 {
        self.specials.sep_id
    }
    fn mask_id(&self) -> u32 {
        self.specials.mask_id
    }
    fn mask_text(&self) -> &str {
        &self.specials.mask_token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_apply_shapes() {
        assert_eq!(
            ChatTemplate::ChatMl.apply("hola"),
            "<|im_start|>user\nhola<|im_end|>\n<|im_start|>assistant\n"
        );
        assert_eq!(ChatTemplate::Mistral.apply("hola"), "[INST] hola [/INST]");
        assert_eq!(ChatTemplate::Plain.apply("hola"), "hola\n");
        assert!(ChatTemplate::Llama3.apply("hola").contains("<|start_header_id|>user"));
    }

    #[test]
    fn plain_template_has_no_stop_tokens() {
        assert!(ChatTemplate::Plain.stop_tokens().is_empty());
        assert!(!ChatTemplate::ChatMl.stop_tokens().is_empty());
    }
}

/// **El guard que faltaba.** Tokenizar con pesos de verdad y comparar con ids concretos.
///
/// Todo lo de este archivo tenía tests, y ninguno agarró que la familia SentencePiece estaba rota:
/// los tests eran sobre el JSON que se armaba, no sobre lo que salía. `The capital of France is`
/// se partía en `▁T|he|▁c|ap|it|al|…` y el modelo respondía basura sin que nada fallara.
///
/// Un tokenizer se prueba con un texto y una lista de ids. No hay otra forma.
#[cfg(test)]
mod live {
    use super::*;

    fn open(var: &str) -> Option<(GgufFile, Tokenizer)> {
        let path = std::env::var(var).ok()?;
        let gguf = GgufFile::open(&path).expect("abrir el gguf");
        let tok = Tokenizer::from_gguf(&gguf).expect("tokenizer");
        Some((gguf, tok))
    }

    /// gemma3: SentencePiece con scores de rango, que es el caso que rompía.
    #[test]
    fn gemma3_tokenizes_words_and_not_fragments() {
        let Some((gguf, tok)) = open("SYNSEMA_TEST_GEMMA3") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GEMMA3=/ruta/al/gguf de gemma3");
            return;
        };
        assert_eq!(tok.family(), "spm");

        // Los ids reales del vocabulario de Gemma 3. Cinco palabras, cinco tokens.
        let ids = tok.encode("The capital of France is").expect("encode");
        assert_eq!(
            ids,
            vec![818, 5279, 529, 7001, 563],
            "si esto se vuelve una lista larga de fragmentos, la segmentación volvió a romperse"
        );
        // Sin espacio de adelante: gemma3 declara `add_space_prefix = 0`, y lo respetamos en vez
        // de asumir el default de SentencePiece. Esa diferencia mueve el primer token de `▁The`
        // (669) a `The` (818), que es lo que hace la referencia.
        assert_eq!(tok.decode(&ids).expect("decode"), "The capital of France is");

        // Los especiales del chat template dan UN token cada uno.
        let tpl = ChatTemplate::detect(&gguf, &tok);
        assert_eq!(tpl, ChatTemplate::Gemma, "gemma3 tiene su propia plantilla");
        let full = tok.encode_prompt(&tpl.apply("The capital of France is")).expect("prompt");
        assert_eq!(full[0], 2, "el `<bos>` va adelante: gemma declara add_bos_token");
        assert_eq!(full[1], 105, "<start_of_turn> es un solo token");
        assert!(full.contains(&106), "<end_of_turn> también");
        assert_eq!(full.len(), 14, "el prompt entero, sin fragmentar: {:?}", full);
    }

    /// El byte-fallback: lo que no está en el vocabulario se emite byte a byte, no como `<unk>`.
    #[test]
    fn gemma3_falls_back_to_bytes_and_round_trips() {
        let Some((_, tok)) = open("SYNSEMA_TEST_GEMMA3") else { return };
        for text in ["hola ñandú", "日本語", "emoji 🙂 y más", "a\tb\nc"] {
            let ids = tok.encode(text).expect("encode");
            let back = tok.decode(&ids).expect("decode");
            assert_eq!(back.trim_start(), text, "no sobrevivió el viaje: {:?}", ids);
        }
    }

    /// Y la familia BPE sigue igual: es la que ya andaba, y conviene que se note si se mueve.
    #[test]
    fn the_bpe_family_is_untouched() {
        let Some((_, tok)) = open("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        assert_eq!(tok.family(), "bpe");
        let ids = tok.encode("The capital of France is").expect("encode");
        assert_eq!(ids.len(), 5, "una palabra por token: {:?}", ids);
        assert_eq!(tok.decode(&ids).expect("decode"), "The capital of France is");
        // qwen declara `add_bos_token = 0`: no se le agrega nada.
        assert_eq!(tok.encode_prompt("hola").expect("prompt"), tok.encode("hola").expect("encode"));
    }
}

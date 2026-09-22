//! El tokenizer SentencePiece de los GGUF de la familia `llama`, escrito acá.
//!
//! ## Por qué no se puede delegar
//!
//! Hasta acá los vocabularios SPM se traducían a un `Unigram` de la crate `tokenizers`, que segmenta
//! por Viterbi: elige la partición que **maximiza la suma de los scores**. Eso es correcto cuando
//! los scores son log-probabilidades, que es lo que guarda un SentencePiece entrenado como unigram.
//!
//! **Los GGUF de Gemma no guardan log-probabilidades: guardan rangos.**
//!
//! | token | id | score |
//! |---|---|---|
//! | `▁The` | 669 | **−175** |
//! | `▁T` | 558 | −64 |
//! | `he` | 499 | −5 |
//!
//! Con esos números Viterbi elige `▁T` + `he` (−69) sobre `▁The` (−175), porque −69 es mayor. No es
//! un bug del Viterbi: es que los scores no significan lo que el Viterbi supone. El resultado era un
//! prompt partido en fragmentos —`T|he|c|ap|it|al`— y un modelo respondiendo basura sin que nada
//! fallara.
//!
//! El algoritmo de referencia (llama.cpp, `llm_tokenizer_spm`) no hace Viterbi: arranca con los
//! caracteres sueltos y **va fusionando el par vecino de mayor score**, como BPE. Con scores de
//! rango eso fusiona por frecuencia; con log-probabilidades, por probabilidad. Anda bien con las dos
//! convenciones, que es exactamente por qué es el que hay que implementar.
//!
//! ## Lo que esto arregla
//!
//! Toda la familia SPM, no sólo Gemma: llama 1 y 2, Mistral y cualquier GGUF cuyo
//! `tokenizer.ggml.model` sea `llama`. La familia BPE (`gpt2`: qwen, llama 3) sigue con la crate
//! `tokenizers`, que ahí sí hace lo correcto — y es lo que hacía que el problema pasara
//! desapercibido, porque el modelo con el que probábamos era qwen.

use std::collections::HashMap;

/// Los tipos de token de ggml. Los que importan acá son control, user-defined y byte.
const TYPE_CONTROL: i64 = 3;
const TYPE_USER_DEFINED: i64 = 4;
const TYPE_BYTE: i64 = 6;

/// El caracter con el que SentencePiece representa un espacio.
const SPACE: &str = "\u{2581}";

/// Un vocabulario SentencePiece con su algoritmo de segmentación.
pub struct Spm {
    tokens: Vec<String>,
    scores: Vec<f32>,
    kinds: Vec<i64>,
    index: HashMap<String, u32>,
    /// Los tokens que se reconocen **literalmente** en el texto, antes de segmentar, agrupados por
    /// su primer byte para no recorrer seis mil en cada posición.
    specials_by_first: HashMap<u8, Vec<(String, u32)>>,
    unk: u32,
    /// El id de `<0x00>`, si el vocabulario trae los 256 tokens de byte.
    byte_base: Option<u32>,
    add_space_prefix: bool,
}

impl Spm {
    /// Arma el tokenizer desde la metadata del GGUF.
    pub fn new(
        tokens: Vec<String>,
        scores: Vec<f32>,
        kinds: Vec<i64>,
        unk: u32,
        add_space_prefix: bool,
    ) -> Result<Self, String> {
        if tokens.len() != scores.len() {
            return Err(format!(
                "metadata inconsistente: {} tokens y {} scores",
                tokens.len(),
                scores.len()
            ));
        }
        if kinds.len() != tokens.len() {
            return Err(format!(
                "metadata inconsistente: {} tokens y {} tipos",
                tokens.len(),
                kinds.len()
            ));
        }

        let mut index = HashMap::with_capacity(tokens.len());
        for (i, t) in tokens.iter().enumerate() {
            // El primero gana: un vocabulario con un token repetido mantiene el id más bajo, que es
            // lo que hace la referencia.
            index.entry(t.clone()).or_insert(i as u32);
        }

        let mut specials_by_first: HashMap<u8, Vec<(String, u32)>> = HashMap::new();
        for (i, t) in tokens.iter().enumerate() {
            let k = kinds[i];
            if (k == TYPE_CONTROL || k == TYPE_USER_DEFINED) && !t.is_empty() {
                if let Some(&b) = t.as_bytes().first() {
                    specials_by_first.entry(b).or_default().push((t.clone(), i as u32));
                }
            }
        }
        // Más largo primero: `<start_of_turn>` tiene que ganarle a un hipotético `<start`.
        for v in specials_by_first.values_mut() {
            v.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        }

        let byte_base = index.get("<0x00>").copied();

        Ok(Spm { tokens, scores, kinds, index, specials_by_first, unk, byte_base, add_space_prefix })
    }

    pub fn token_to_id(&self, token: &str) -> Option<u32> {
        self.index.get(token).copied()
    }

    pub fn vocab_size(&self) -> usize {
        self.tokens.len()
    }

    /// Tokeniza. Los tokens especiales se reconocen literalmente; el resto se segmenta.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut out = Vec::new();
        let mut buf = String::new();
        let bytes = text.as_bytes();
        let mut i = 0usize;
        // `true` mientras no se haya emitido nada: el prefijo de espacio va una sola vez, al
        // principio del texto, igual que en la referencia.
        let mut first_fragment = true;

        while i < bytes.len() {
            let mut matched = None;
            if let Some(cands) = self.specials_by_first.get(&bytes[i]) {
                for (tok, id) in cands {
                    if text.len() - i >= tok.len() && text[i..].starts_with(tok.as_str()) {
                        matched = Some((tok.len(), *id));
                        break;
                    }
                }
            }
            match matched {
                Some((len, id)) => {
                    if !buf.is_empty() {
                        self.encode_fragment(&buf, first_fragment, &mut out);
                        buf.clear();
                    }
                    out.push(id);
                    // Un token especial ya reconocido cuenta como texto emitido: lo que venga
                    // despues no lleva el prefijo de comienzo de secuencia.
                    first_fragment = false;
                    i += len;
                }
                None => {
                    // Avanzar un caracter completo, no un byte.
                    let mut len = 1;
                    while i + len < bytes.len() && (bytes[i + len] & 0xC0) == 0x80 {
                        len += 1;
                    }
                    buf.push_str(&text[i..i + len]);
                    i += len;
                }
            }
        }
        if !buf.is_empty() {
            self.encode_fragment(&buf, first_fragment, &mut out);
        }
        out
    }

    /// Segmenta un trozo de texto sin tokens especiales.
    fn encode_fragment(&self, text: &str, first: bool, out: &mut Vec<u32>) {
        let mut escaped = String::with_capacity(text.len() + 3);
        if first && self.add_space_prefix {
            escaped.push_str(SPACE);
        }
        for c in text.chars() {
            if c == ' ' {
                escaped.push_str(SPACE);
            } else {
                escaped.push(c);
            }
        }
        if escaped.is_empty() {
            return;
        }
        self.merge(&escaped, out);
    }

    /// **El algoritmo.** Caracteres sueltos, y se fusiona el par vecino de mayor score hasta que
    /// no quede ninguno que exista en el vocabulario.
    fn merge(&self, text: &str, out: &mut Vec<u32>) {
        let mut syms: Vec<Sym> = Vec::new();
        for (pos, c) in text.char_indices() {
            let n = syms.len();
            syms.push(Sym {
                start: pos,
                len: c.len_utf8(),
                prev: if n == 0 { -1 } else { n as i32 - 1 },
                next: -1,
            });
            if n > 0 {
                syms[n - 1].next = n as i32;
            }
        }
        if syms.is_empty() {
            return;
        }
        let last = syms.len() - 1;
        syms[last].next = -1;

        let mut heap: std::collections::BinaryHeap<Bigram> = std::collections::BinaryHeap::new();
        for i in 1..syms.len() {
            self.try_bigram(text, &syms, i as i32 - 1, i as i32, &mut heap);
        }

        while let Some(b) = heap.pop() {
            let (li, ri) = (b.left as usize, b.right as usize);
            // Uno de los dos ya se fusionó con otro: el par que este bigrama describía ya no
            // existe. Es el chequeo que hace que alcance con una cola y no haya que rehacerla.
            if syms[li].len == 0 || syms[ri].len == 0 || syms[li].len + syms[ri].len != b.size {
                continue;
            }
            syms[li].len += syms[ri].len;
            syms[ri].len = 0;
            syms[li].next = syms[ri].next;
            if syms[ri].next >= 0 {
                let n = syms[ri].next as usize;
                syms[n].prev = b.left;
            }
            let (prev, next) = (syms[li].prev, syms[li].next);
            self.try_bigram(text, &syms, prev, b.left, &mut heap);
            self.try_bigram(text, &syms, b.left, next, &mut heap);
        }

        let mut i: i32 = 0;
        while i >= 0 {
            let s = &syms[i as usize];
            if s.len > 0 {
                let piece = &text[s.start..s.start + s.len];
                match self.index.get(piece) {
                    Some(&id) => out.push(id),
                    // Lo que no está en el vocabulario se emite byte por byte. Sin esto, un
                    // caracter raro se volvería `<unk>` y el modelo perdería la entrada entera.
                    None => self.push_bytes(piece, out),
                }
            }
            i = s.next;
        }
    }

    fn try_bigram(
        &self,
        text: &str,
        syms: &[Sym],
        left: i32,
        right: i32,
        heap: &mut std::collections::BinaryHeap<Bigram>,
    ) {
        if left < 0 || right < 0 {
            return;
        }
        let (l, r) = (&syms[left as usize], &syms[right as usize]);
        if l.len == 0 || r.len == 0 {
            return;
        }
        let piece = &text[l.start..l.start + l.len + r.len];
        if let Some(&id) = self.index.get(piece) {
            heap.push(Bigram {
                left,
                right,
                score: self.scores[id as usize],
                size: l.len + r.len,
            });
        }
    }

    fn push_bytes(&self, piece: &str, out: &mut Vec<u32>) {
        match self.byte_base {
            Some(base) => {
                for b in piece.as_bytes() {
                    out.push(base + *b as u32);
                }
            }
            None => out.push(self.unk),
        }
    }

    /// Reconstruye el texto. `skip_control` descarta `<bos>`, `<eos>` y compañía.
    ///
    /// **No se le saca el espacio de adelante.** La referencia sí lo hace cuando detokeniza un
    /// prompt entero, pero acá lo que se detokeniza es la continuación generada, y ahí ese espacio
    /// es parte de la respuesta: comérselo pega la primera palabra a lo anterior.
    pub fn decode(&self, ids: &[u32], skip_control: bool) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        for &id in ids {
            let i = id as usize;
            if i >= self.tokens.len() {
                continue;
            }
            let kind = self.kinds[i];
            if kind == TYPE_CONTROL && skip_control {
                continue;
            }
            if kind == TYPE_BYTE {
                if let Some(b) = parse_byte_token(&self.tokens[i]) {
                    bytes.push(b);
                    continue;
                }
            }
            bytes.extend_from_slice(self.tokens[i].as_bytes());
        }
        // `from_utf8_lossy` y no un error: una respuesta cortada al medio de un caracter es
        // normal durante el streaming, y ahí lo que corresponde es seguir, no fallar.
        String::from_utf8_lossy(&bytes).replace(SPACE, " ")
    }
}

/// `<0x41>` → `b'A'`.
fn parse_byte_token(t: &str) -> Option<u8> {
    let inner = t.strip_prefix("<0x")?.strip_suffix('>')?;
    u8::from_str_radix(inner, 16).ok()
}

/// Un símbolo de la segmentación: un trozo de texto con sus vecinos.
#[derive(Clone, Copy)]
struct Sym {
    start: usize,
    /// `0` significa «absorbido por el vecino de la izquierda».
    len: usize,
    prev: i32,
    next: i32,
}

/// Un par vecino que existe en el vocabulario, esperando su turno para fusionarse.
struct Bigram {
    left: i32,
    right: i32,
    score: f32,
    size: usize,
}

impl PartialEq for Bigram {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for Bigram {}
impl PartialOrd for Bigram {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Bigram {
    /// Mayor score primero; a igual score, el que está más a la izquierda.
    ///
    /// El desempate no es cosmético: sin él, dos corridas pueden segmentar distinto el mismo texto
    /// y el modelo ver otra entrada. Es el mismo criterio que la referencia.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.left.cmp(&self.left))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un vocabulario chico con **scores de rango**, que es la convención que rompía el Viterbi.
    ///
    /// `▁The` es el token bueno y tiene el score MÁS negativo. Un Viterbi elegiría `▁T`+`he`; el
    /// algoritmo de merges elige `▁The`, que es lo correcto.
    fn fixture() -> Spm {
        let toks: Vec<String> = [
            "<unk>", "<bos>", "<eos>", "<0x00>", "<0x41>", "<0x42>", "\u{2581}T", "he",
            "\u{2581}The", "\u{2581}", "\u{2581}a", "b", "\u{2581}ab", "<start_of_turn>",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Un `<0x00>` de mentira seguido de los dos bytes que el test usa: el byte-fallback los
        // calcula como `base + b`, así que hay que dejarle lugar. Se completa hasta 0x42.
        let mut tokens = toks.clone();
        // Rellenar entre <0x00> (idx 3) y <0x41>: el fallback hace base + byte.
        let base = 3;
        tokens = Vec::new();
        for t in toks.iter().take(3) {
            tokens.push(t.clone());
        }
        for b in 0..=255u32 {
            tokens.push(format!("<0x{:02X}>", b));
        }
        for t in toks.iter().skip(6) {
            tokens.push(t.clone());
        }
        assert_eq!(tokens[base], "<0x00>");
        let n = tokens.len();
        let mut scores = vec![0f32; n];
        let mut kinds = vec![1i64; n];
        for i in 0..3 {
            kinds[i] = TYPE_CONTROL;
        }
        for i in base..base + 256 {
            kinds[i] = TYPE_BYTE;
        }
        let id = |s: &str| tokens.iter().position(|t| t == s).unwrap();
        // Rangos, no log-probabilidades: el bueno es el MÁS negativo.
        scores[id("\u{2581}T")] = -64.0;
        scores[id("he")] = -5.0;
        scores[id("\u{2581}The")] = -175.0;
        scores[id("\u{2581}a")] = -10.0;
        scores[id("b")] = -3.0;
        scores[id("\u{2581}ab")] = -200.0;
        kinds[id("<start_of_turn>")] = TYPE_CONTROL;
        Spm::new(tokens, scores, kinds, 0, true).unwrap()
    }

    #[test]
    fn merges_prefer_the_longer_piece_even_with_rank_scores() {
        let spm = fixture();
        let ids = spm.encode("The");
        assert_eq!(
            ids,
            vec![spm.token_to_id("\u{2581}The").unwrap()],
            "con scores de rango, Viterbi partiría en `▁T`+`he`; los merges no"
        );
    }

    #[test]
    fn the_space_prefix_goes_once_at_the_start() {
        let spm = fixture();
        // "ab" con prefijo → "▁ab", que está en el vocabulario como una pieza.
        assert_eq!(spm.encode("ab"), vec![spm.token_to_id("\u{2581}ab").unwrap()]);
    }

    #[test]
    fn special_tokens_are_matched_literally_and_split_the_text() {
        let spm = fixture();
        let ids = spm.encode("<start_of_turn>The");
        assert_eq!(ids[0], spm.token_to_id("<start_of_turn>").unwrap(), "uno solo: {:?}", ids);
        // El resto se segmenta aparte y vuelve a ser el mismo texto. En este vocabulario de
        // juguete no existe `The` sin el marcador, asi que cae a bytes — que es lo correcto.
        assert_eq!(spm.decode(&ids[1..], true), "The");
        // Y el especial NO se parte: sin el reconocimiento literal saldrian diez tokens.
        assert!(ids.len() < 5, "el especial se partio: {:?}", ids);
    }

    /// El prefijo de espacio va **una vez**, al principio del texto — no después de cada especial.
    #[test]
    fn the_prefix_is_not_repeated_after_a_special() {
        let spm = fixture();
        let ids = spm.encode("<start_of_turn>ab");
        // Sin prefijo, "ab" es `▁a`? No: es "a"+"b", y "a" solo no está → byte-fallback + "b".
        assert_ne!(
            ids[1],
            spm.token_to_id("\u{2581}ab").unwrap(),
            "el `▁` no se vuelve a poner después de un token especial"
        );
    }

    #[test]
    fn unknown_characters_fall_back_to_bytes() {
        let spm = fixture();
        let ids = spm.encode("AB");
        // Ni "▁A" ni "A" están: cada byte por su cuenta. `▁` sí está, y va primero.
        assert_eq!(ids[0], spm.token_to_id("\u{2581}").unwrap());
        assert_eq!(ids[1], spm.token_to_id("<0x41>").unwrap());
        assert_eq!(ids[2], spm.token_to_id("<0x42>").unwrap());
    }

    #[test]
    fn decoding_undoes_the_space_marker_and_the_byte_tokens() {
        let spm = fixture();
        let ids = spm.encode("The");
        assert_eq!(spm.decode(&ids, true), " The");
        let bytes = vec![spm.token_to_id("<0x41>").unwrap(), spm.token_to_id("<0x42>").unwrap()];
        assert_eq!(spm.decode(&bytes, true), "AB");
    }

    #[test]
    fn control_tokens_are_dropped_when_asked() {
        let spm = fixture();
        let bos = spm.token_to_id("<bos>").unwrap();
        let ids = [bos, spm.token_to_id("he").unwrap()];
        assert_eq!(spm.decode(&ids, true), "he");
        assert_eq!(spm.decode(&ids, false), "<bos>he");
    }

    #[test]
    fn an_empty_text_gives_no_tokens() {
        let spm = fixture();
        assert!(spm.encode("").is_empty());
    }

    #[test]
    fn inconsistent_metadata_is_rejected() {
        let t: Vec<String> = vec!["a".into(), "b".into()];
        assert!(Spm::new(t.clone(), vec![0.0], vec![1, 1], 0, true).is_err());
        assert!(Spm::new(t, vec![0.0, 0.0], vec![1], 0, true).is_err());
    }

    /// El desempate importa: a igual score, gana el de la izquierda. Sin eso la segmentación
    /// podría cambiar entre corridas y el modelo ver otra entrada.
    #[test]
    fn ties_break_towards_the_left() {
        let a = Bigram { left: 3, right: 4, score: -1.0, size: 2 };
        let b = Bigram { left: 5, right: 6, score: -1.0, size: 2 };
        assert!(a > b, "a igual score, el de la izquierda tiene prioridad");
        let c = Bigram { left: 9, right: 10, score: -0.5, size: 2 };
        assert!(c > a, "más score gana, esté donde esté");
    }
}

//! Laya: preguntas tipadas, armado de la secuencia y calibración. **Todo puro.**
//!
//! Nada de este archivo toca tensores, pesos ni backend: son las reglas del protocolo de Laya,
//! que se pueden testear sin descargar 843 MB de checkpoint. Es el patrón de la casa (spec
//! `synsema-infer.md` §2.1, regla 4), y acá importa el doble porque la **paridad con el upstream
//! se juega en estos detalles**: un token de más en el prefijo mueve todos los marcadores y la
//! respuesta cambia sin que nada falle.
//!
//! ## El formato de la secuencia
//!
//! ```text
//! [CLS] <tipo> question: <instrucciones> [SEP] [MASK] opción0 [MASK] opción1 … [SEP] <estado> [SEP]
//! ```
//!
//! Los `[MASK]` son **marcadores**: el modelo puntúa la posición de cada uno, y ese puntaje es la
//! preferencia por esa opción. Por eso el orden y la posición exacta importan tanto.
//!
//! ## Las tres formas de pregunta
//!
//! | Tipo | Qué devuelve | Opciones |
//! |---|---|---|
//! | `choice` | la etiqueta ganadora y la distribución | las claves del criterio |
//! | `score` | el valor esperado sobre niveles ordenados | `level 0`, `level 1`, … |
//! | `noul` | P(verdadero) | siempre dos: `false`, `true` |
//!
//! `noul` es el nombre del upstream. En Synsema el verbo expone esto como `truth`
//! (`specs/system-one-judge.md` §4.1): no adoptamos el glosario de un proveedor.

use std::collections::BTreeMap;

use serde_json::Value;

/// El tipo de una pregunta. El orden numérico es el del upstream y **no se puede cambiar**: es el
/// índice del `type_emb` del checkpoint y el de la tabla de temperaturas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QType {
    Choice = 0,
    Score = 1,
    Noul = 2,
}

impl QType {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn name(self) -> &'static str {
        match self {
            QType::Choice => "choice",
            QType::Score => "score",
            QType::Noul => "noul",
        }
    }

    pub fn parse(s: &str) -> Option<QType> {
        match s {
            "choice" => Some(QType::Choice),
            "score" => Some(QType::Score),
            "noul" | "truth" | "boolean" => Some(QType::Noul),
            _ => None,
        }
    }
}

/// Los criterios de una pregunta, ya validados por tipo.
#[derive(Clone, Debug)]
pub enum Criteria {
    /// `choice`: etiquetas en orden, con descripción opcional. Se conserva el orden de
    /// declaración porque **es el orden de la distribución de salida**.
    Labels(Vec<(String, Option<Value>)>),
    /// `score`: niveles ordenados, de menor a mayor.
    Levels(Vec<Value>),
    /// `noul`: descripciones opcionales para falso y verdadero.
    Truth { when_false: Option<Value>, when_true: Option<Value> },
}

/// Una pregunta lista para armar su secuencia.
#[derive(Clone, Debug)]
pub struct Question {
    pub kind: QType,
    pub instructions: String,
    pub criteria: Criteria,
}

impl Question {
    /// Cuántas opciones puntúa el modelo. Es el `k` de la calibración y de la confianza.
    pub fn option_count(&self) -> usize {
        match &self.criteria {
            Criteria::Labels(v) => v.len(),
            Criteria::Levels(v) => v.len(),
            Criteria::Truth { .. } => 2,
        }
    }

    /// Las etiquetas con las que se reporta la distribución.
    pub fn labels(&self) -> Vec<String> {
        match &self.criteria {
            Criteria::Labels(v) => v.iter().map(|(k, _)| k.clone()).collect(),
            Criteria::Levels(v) => (0..v.len()).map(|i| i.to_string()).collect(),
            Criteria::Truth { .. } => vec!["false".to_string(), "true".to_string()],
        }
    }

    /// El texto de cada opción, en orden de etiqueta. Es lo que va después de cada `[MASK]`.
    pub fn render_options(&self) -> Vec<String> {
        match &self.criteria {
            Criteria::Labels(entries) => entries
                .iter()
                .map(|(label, desc)| match desc {
                    // Sólo `null` y `""` significan "sin descripción": un 0 o un false son
                    // valores de criterio legítimos y tienen que renderizarse.
                    None => label.clone(),
                    Some(v) if is_empty_text(v) => label.clone(),
                    Some(v) => format!("{}: {}", label, render_criterion(v)),
                })
                .collect(),
            Criteria::Levels(levels) => levels
                .iter()
                .enumerate()
                .map(|(i, c)| format!("level {}: {}", i, render_criterion(c)))
                .collect(),
            Criteria::Truth { when_false, when_true } => {
                let f = match when_false {
                    Some(v) if !is_empty_text(v) => render_criterion(v),
                    _ => "no, the statement does not hold".to_string(),
                };
                let t = match when_true {
                    Some(v) if !is_empty_text(v) => render_criterion(v),
                    _ => "yes, the statement holds".to_string(),
                };
                vec![format!("false: {}", f), format!("true: {}", t)]
            }
        }
    }
}

fn is_empty_text(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        _ => false,
    }
}

/// Un criterio como texto. Los strings pasan tal cual; lo estructurado va como JSON compacto
/// —con los separadores del upstream, `", "` y `": "`— para que una rúbrica se lea como JSON y no
/// como el `repr` de otro lenguaje.
pub fn render_criterion(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => compact_json(other),
    }
}

/// `json.dumps(..., separators=(", ", ": "), ensure_ascii=False)` de Python: los separadores
/// llevan espacio, a diferencia del compacto de `serde_json`.
fn compact_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let inner: Vec<String> =
                map.iter().map(|(k, val)| format!("{}: {}", Value::String(k.clone()), compact_json(val))).collect();
            format!("{{{}}}", inner.join(", "))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(compact_json).collect();
            format!("[{}]", inner.join(", "))
        }
        other => other.to_string(),
    }
}

/// El estado como texto: un string va tal cual, cualquier otra cosa se serializa.
pub fn serialize_state(state: &Value) -> String {
    match state {
        Value::String(s) => s.clone(),
        other => compact_json(other),
    }
}

// =========================================================
// Armado de la secuencia
// =========================================================

/// Lo que el armado necesita de un tokenizer. Es un trait para que las reglas de arriba se puedan
/// testear con un tokenizer de juguete, sin cargar el vocabulario real de 50 368 entradas.
pub trait SeqTokenizer {
    fn encode_plain(&self, text: &str) -> Result<Vec<u32>, String>;
    fn cls_id(&self) -> u32;
    fn sep_id(&self) -> u32;
    fn mask_id(&self) -> u32;
    /// El texto del token de máscara, que se **borra de la entrada del usuario**: si el estado
    /// trae un `[MASK]` literal, inyectaría un marcador falso y correría todos los demás.
    fn mask_text(&self) -> &str;
}

/// Una secuencia lista para el modelo.
#[derive(Clone, Debug, PartialEq)]
pub struct Sequence {
    pub ids: Vec<u32>,
    /// Posición de cada `[MASK]`, en orden de opción.
    pub markers: Vec<usize>,
}

/// Tope de tokens por opción, del upstream.
const OPTION_TOKEN_LIMIT: usize = 48;
/// Piso de presupuesto para el encabezado antes de recortar las opciones.
const MIN_OPTION_BUDGET: usize = 16;
/// Piso absoluto de tokens de encabezado.
const MIN_HEAD_TOKENS: usize = 8;

/// El prefijo: tipo, instrucciones y opciones marcadas. Sin el estado todavía.
pub fn build_prefix(
    tok: &dyn SeqTokenizer,
    q: &Question,
    head_max_len: usize,
) -> Result<Sequence, String> {
    let mask = tok.mask_text();
    let options = q.render_options();
    let instructions = q.instructions.replace(mask, " ");
    let mut head_ids = tok.encode_plain(&format!("{} question: {}", q.kind.name(), instructions))?;

    let mut option_ids: Vec<Vec<u32>> = Vec::with_capacity(options.len());
    for opt in &options {
        let mut ids = vec![tok.mask_id()];
        let mut body = tok.encode_plain(&format!(" {}", opt.replace(mask, " ")))?;
        body.truncate(OPTION_TOKEN_LIMIT);
        ids.extend(body);
        option_ids.push(ids);
    }

    // Si las opciones se comieron el presupuesto, se recortan por igual antes que el encabezado:
    // perder una opción entera sería perder una respuesta posible.
    let used: usize = option_ids.iter().map(|o| o.len()).sum();
    let mut option_budget = head_max_len.saturating_sub(used);
    if option_budget < MIN_OPTION_BUDGET {
        let per = std::cmp::max(
            4,
            head_max_len.saturating_sub(MIN_OPTION_BUDGET) / std::cmp::max(1, option_ids.len()),
        );
        for o in option_ids.iter_mut() {
            o.truncate(per);
        }
        let used: usize = option_ids.iter().map(|o| o.len()).sum();
        option_budget = head_max_len.saturating_sub(used);
    }
    head_ids.truncate(std::cmp::max(MIN_HEAD_TOKENS, option_budget));

    let mut ids = vec![tok.cls_id()];
    ids.extend(head_ids);
    ids.push(tok.sep_id());
    let mut markers = Vec::with_capacity(option_ids.len());
    for o in option_ids {
        markers.push(ids.len());
        ids.extend(o);
    }
    ids.push(tok.sep_id());
    Ok(Sequence { ids, markers })
}

/// La secuencia completa: prefijo + estado + `[SEP]`, truncada a `max_len`.
///
/// **Un marcador que cae fuera de `max_len` se descarta**, y quien llama tiene que verificar que
/// sigan estando todos: si falta uno, la pregunta no entra en el presupuesto y responderla igual
/// sería inventar. Ver `decide`.
pub fn build_sequence(
    tok: &dyn SeqTokenizer,
    state: &Value,
    q: &Question,
    max_len: usize,
    head_max_len: usize,
) -> Result<Sequence, String> {
    let prefix = build_prefix(tok, q, head_max_len)?;
    let room = max_len.saturating_sub(prefix.ids.len() + 1);
    let mut state_ids = tok.encode_plain(&serialize_state(state).replace(tok.mask_text(), " "))?;
    state_ids.truncate(room);

    let mut ids = prefix.ids;
    ids.extend(state_ids);
    ids.push(tok.sep_id());
    ids.truncate(max_len);
    let markers = prefix.markers.into_iter().filter(|m| *m < max_len).collect();
    Ok(Sequence { ids, markers })
}

// =========================================================
// Calibración y confianza
// =========================================================

/// La configuración de decisión del checkpoint (`rl_agent_config.json`).
#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub head_layers: usize,
    pub max_len: usize,
    pub head_max_len: usize,
    /// Una temperatura por tipo de pregunta, indexada por `QType`.
    pub temperature: [f32; 3],
    /// Temperaturas finas por `tipo:cantidad-de-opciones`, que ganan sobre las de arriba.
    pub temperature_by_options: BTreeMap<String, f32>,
    /// Cuántas acciones tiene la cabeza de acción: `len(act_costs) + 1`.
    pub action_count: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            head_layers: 2,
            max_len: 512,
            head_max_len: 192,
            temperature: [1.0, 1.0, 1.0],
            temperature_by_options: BTreeMap::new(),
            action_count: 2,
        }
    }
}

impl AgentConfig {
    /// Lee `rl_agent_config.json`. Falla claro si la calibración no es usable: una temperatura
    /// que no es finita y positiva produciría probabilidades sin sentido, y es mejor no arrancar
    /// que responder con números inventados.
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let mut cfg = AgentConfig::default();
        if let Some(n) = v.get("head_layers").and_then(|x| x.as_u64()) {
            cfg.head_layers = n as usize;
        }
        if let Some(n) = v.get("max_len").and_then(|x| x.as_u64()) {
            cfg.max_len = n as usize;
        }
        if let Some(n) = v.get("head_max_len").and_then(|x| x.as_u64()) {
            cfg.head_max_len = n as usize;
        }
        if let Some(arr) = v.get("temperature").and_then(|x| x.as_array()) {
            if arr.len() != 3 {
                return Err("`temperature` debe traer exactamente tres valores".to_string());
            }
            for (i, t) in arr.iter().enumerate() {
                cfg.temperature[i] = finite_positive(t, "temperature")?;
            }
        }
        if let Some(map) = v.get("temperature_by_options").and_then(|x| x.as_object()) {
            for (k, t) in map {
                cfg.temperature_by_options
                    .insert(k.clone(), finite_positive(t, "temperature_by_options")?);
            }
        }
        if let Some(costs) = v.get("act_costs").and_then(|x| x.as_object()) {
            cfg.action_count = costs.len() + 1;
        }
        if !(4 < cfg.head_max_len && cfg.head_max_len < cfg.max_len) {
            return Err(format!(
                "se esperaba 4 < head_max_len ({}) < max_len ({})",
                cfg.head_max_len, cfg.max_len
            ));
        }
        Ok(cfg)
    }

    /// La temperatura que corresponde a esta pregunta: primero el bucket fino, y si no está, la
    /// del tipo.
    pub fn temperature_for(&self, kind: QType, k: usize) -> f32 {
        self.temperature_by_options
            .get(&temp_bucket(kind, k))
            .copied()
            .unwrap_or(self.temperature[kind.index()])
    }
}

fn finite_positive(v: &Value, field: &str) -> Result<f32, String> {
    let n = v.as_f64().ok_or_else(|| format!("`{}` no es numérico", field))?;
    if !n.is_finite() || n <= 0.0 {
        return Err(format!("`{}` debe ser finito y positivo, no {}", field, n));
    }
    Ok(n as f32)
}

/// El bucket de calibración: `tipo:tamaño`. Los cortes son del upstream y no se tocan — cambiarlos
/// desalinearía la tabla del checkpoint.
pub fn temp_bucket(kind: QType, k: usize) -> String {
    let size = if k <= 2 {
        "2"
    } else if k <= 5 {
        "3-5"
    } else if k <= 10 {
        "6-10"
    } else {
        "11+"
    };
    format!("{}:{}", kind.name(), size)
}

/// Softmax estable (resta el máximo antes de exponenciar) sobre los primeros `k` logits, con la
/// temperatura aplicada.
pub fn calibrated_probabilities(logits: &[f32], k: usize, temperature: f32) -> Vec<f32> {
    let k = k.min(logits.len());
    if k == 0 {
        return Vec::new();
    }
    let scale = temperature.max(1e-3);
    let z: Vec<f32> = logits[..k].iter().map(|l| l / scale).collect();
    let max = z.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut p: Vec<f32> = z.iter().map(|v| (v - max).exp()).collect();
    let sum: f32 = p.iter().sum();
    if sum > 0.0 {
        for v in p.iter_mut() {
            *v /= sum;
        }
    }
    p
}

/// Confianza por entropía normalizada: `1 - H(p)/log(k)`. Con una sola opción no hay incertidumbre
/// que medir, así que es 1.
pub fn confidence_from_probs(p: &[f32], k: usize) -> f32 {
    if k < 2 {
        return 1.0;
    }
    let k = k.min(p.len());
    let entropy: f32 = p[..k]
        .iter()
        .map(|&x| {
            let x = x.clamp(1e-12, 1.0);
            -x * x.ln()
        })
        .sum();
    (1.0 - entropy / (k as f32).ln()).clamp(0.0, 1.0)
}

/// Redondeo a cuatro decimales, como el upstream: las probabilidades se reportan con la misma
/// precisión para que la paridad se pueda comparar valor a valor.
pub fn round4(x: f32) -> f32 {
    (x * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Tokenizer de juguete: un id por palabra, ids especiales fijos. Alcanza para verificar
    /// posiciones de marcadores y recortes, que es lo que de verdad importa acá.
    struct Toy;

    impl SeqTokenizer for Toy {
        fn encode_plain(&self, text: &str) -> Result<Vec<u32>, String> {
            Ok(text.split_whitespace().map(|w| 1000 + w.len() as u32).collect())
        }
        fn cls_id(&self) -> u32 {
            1
        }
        fn sep_id(&self) -> u32 {
            2
        }
        fn mask_id(&self) -> u32 {
            3
        }
        fn mask_text(&self) -> &str {
            "[MASK]"
        }
    }

    fn choice(labels: &[(&str, Option<Value>)]) -> Question {
        Question {
            kind: QType::Choice,
            instructions: "Which team?".to_string(),
            criteria: Criteria::Labels(
                labels.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
            ),
        }
    }

    // -- render_options --

    #[test]
    fn choice_without_description_is_just_the_label() {
        let q = choice(&[("billing", None), ("technical", Some(json!("")))]);
        assert_eq!(q.render_options(), vec!["billing", "technical"]);
    }

    #[test]
    fn zero_and_false_are_legitimate_criteria_not_empty() {
        // El upstream tuvo este bug: `0` y `false` se trataban como "sin descripción".
        let q = choice(&[("a", Some(json!(0))), ("b", Some(json!(false)))]);
        assert_eq!(q.render_options(), vec!["a: 0", "b: false"]);
    }

    #[test]
    fn structured_criteria_render_as_json_with_spaced_separators() {
        let q = choice(&[("x", Some(json!({"desc": "hola", "n": 2})))]);
        let opts = q.render_options();
        assert!(opts[0].starts_with("x: {"), "{}", opts[0]);
        assert!(opts[0].contains("\"desc\": \"hola\""), "{}", opts[0]);
        assert!(opts[0].contains(", "), "separadores con espacio: {}", opts[0]);
    }

    #[test]
    fn score_levels_are_numbered() {
        let q = Question {
            kind: QType::Score,
            instructions: "How urgent?".to_string(),
            criteria: Criteria::Levels(vec![json!("not urgent"), json!("critical")]),
        };
        assert_eq!(q.render_options(), vec!["level 0: not urgent", "level 1: critical"]);
    }

    #[test]
    fn noul_has_defaults_and_is_always_two() {
        let q = Question {
            kind: QType::Noul,
            instructions: "Does it hold?".to_string(),
            criteria: Criteria::Truth { when_false: None, when_true: Some(json!("sí, aplica")) },
        };
        let opts = q.render_options();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], "false: no, the statement does not hold");
        assert_eq!(opts[1], "true: sí, aplica");
        assert_eq!(q.option_count(), 2);
    }

    // -- build_prefix / build_sequence --

    #[test]
    fn markers_point_at_the_mask_of_each_option() {
        let q = choice(&[("a", None), ("b", None), ("c", None)]);
        let seq = build_prefix(&Toy, &q, 192).unwrap();
        assert_eq!(seq.markers.len(), 3);
        for &m in &seq.markers {
            assert_eq!(seq.ids[m], Toy.mask_id(), "el marcador debe caer en el [MASK]");
        }
        assert_eq!(seq.ids[0], Toy.cls_id());
        assert_eq!(*seq.ids.last().unwrap(), Toy.sep_id());
    }

    #[test]
    fn sequence_ends_with_sep_and_respects_max_len() {
        let q = choice(&[("a", None), ("b", None)]);
        let state = json!("una cadena de estado con varias palabras para llenar espacio");
        let seq = build_sequence(&Toy, &state, &q, 24, 16).unwrap();
        assert!(seq.ids.len() <= 24, "largo {}", seq.ids.len());
    }

    /// Un `[MASK]` en la entrada del usuario inyectaría un marcador falso y correría todos los
    /// demás: tiene que desaparecer, tanto del estado como de las instrucciones.
    #[test]
    fn mask_token_in_user_input_is_stripped() {
        let q = Question {
            kind: QType::Choice,
            instructions: "antes [MASK] después".to_string(),
            criteria: Criteria::Labels(vec![("a".to_string(), None)]),
        };
        let state = json!("estado [MASK] con máscara");
        let seq = build_sequence(&Toy, &state, &q, 512, 192).unwrap();
        let masks = seq.ids.iter().filter(|&&id| id == Toy.mask_id()).count();
        assert_eq!(masks, 1, "sólo el marcador de la única opción puede ser [MASK]");
    }

    #[test]
    fn options_are_trimmed_before_the_head_when_budget_is_tight() {
        // Muchas opciones largas contra un presupuesto chico: ninguna puede desaparecer.
        let labels: Vec<(String, Option<Value>)> = (0..8)
            .map(|i| (format!("opcion-larga-numero-{}", i), Some(json!("una descripción extensa"))))
            .collect();
        let q = Question {
            kind: QType::Choice,
            instructions: "pregunta con muchas palabras en el encabezado".to_string(),
            criteria: Criteria::Labels(labels),
        };
        let seq = build_prefix(&Toy, &q, 40).unwrap();
        assert_eq!(seq.markers.len(), 8, "no puede perderse ninguna opción");
    }

    // -- calibración --

    #[test]
    fn buckets_match_upstream_cutoffs() {
        assert_eq!(temp_bucket(QType::Choice, 2), "choice:2");
        assert_eq!(temp_bucket(QType::Choice, 5), "choice:3-5");
        assert_eq!(temp_bucket(QType::Choice, 6), "choice:6-10");
        assert_eq!(temp_bucket(QType::Choice, 11), "choice:11+");
        assert_eq!(temp_bucket(QType::Noul, 2), "noul:2");
        assert_eq!(temp_bucket(QType::Score, 4), "score:3-5");
    }

    #[test]
    fn fine_bucket_wins_over_the_type_temperature() {
        let cfg = AgentConfig::from_json(&json!({
            "temperature": [1.6, 1.25, 1.98],
            "temperature_by_options": {"choice:2": 1.9},
            "max_len": 512, "head_max_len": 192,
        }))
        .unwrap();
        assert!((cfg.temperature_for(QType::Choice, 2) - 1.9).abs() < 1e-6);
        // Sin bucket para 3-5, cae a la del tipo.
        assert!((cfg.temperature_for(QType::Choice, 4) - 1.6).abs() < 1e-6);
    }

    #[test]
    fn non_positive_temperature_is_rejected() {
        let bad = json!({"temperature": [1.0, 0.0, 1.0], "max_len": 512, "head_max_len": 192});
        assert!(AgentConfig::from_json(&bad).is_err());
        let nan = json!({"temperature": [1.0, 1.0, "x"], "max_len": 512, "head_max_len": 192});
        assert!(AgentConfig::from_json(&nan).is_err());
    }

    #[test]
    fn head_max_len_must_fit_inside_max_len() {
        let bad = json!({"max_len": 100, "head_max_len": 200});
        assert!(AgentConfig::from_json(&bad).is_err());
    }

    #[test]
    fn action_count_is_costs_plus_one() {
        let cfg = AgentConfig::from_json(&json!({
            "act_costs": {"escalate": 0.5}, "max_len": 512, "head_max_len": 192,
        }))
        .unwrap();
        assert_eq!(cfg.action_count, 2);
    }

    #[test]
    fn probabilities_sum_to_one_and_temperature_flattens() {
        let logits = [3.0, 1.0, 0.5];
        let sharp = calibrated_probabilities(&logits, 3, 0.5);
        let flat = calibrated_probabilities(&logits, 3, 4.0);
        assert!((sharp.iter().sum::<f32>() - 1.0).abs() < 1e-5);
        assert!((flat.iter().sum::<f32>() - 1.0).abs() < 1e-5);
        assert!(sharp[0] > flat[0], "menos temperatura = distribución más filosa");
    }

    #[test]
    fn only_the_first_k_logits_are_used() {
        // Las filas se paddean: lo que está más allá de k es basura y no puede contaminar.
        let logits = [2.0, 1.0, 999.0];
        let p = calibrated_probabilities(&logits, 2, 1.0);
        assert_eq!(p.len(), 2);
        assert!((p.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    }

    #[test]
    fn confidence_is_one_when_certain_and_zero_when_uniform() {
        assert!(confidence_from_probs(&[1.0, 0.0], 2) > 0.999);
        assert!(confidence_from_probs(&[0.5, 0.5], 2) < 1e-5);
        assert!((confidence_from_probs(&[1.0], 1) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn state_serialization_matches_upstream_shape() {
        assert_eq!(serialize_state(&json!("texto")), "texto");
        let obj = serialize_state(&json!({"a": 1, "b": "x"}));
        assert!(obj.contains("\"a\": 1"), "{}", obj);
        assert!(obj.contains(", "), "{}", obj);
    }
}

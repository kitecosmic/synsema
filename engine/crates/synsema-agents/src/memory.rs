//! Memoria persistente del agente. Port de `synsema/agents/memory.py`.
//!
//! Preferencias/reglas/learnings con persistencia JSON. Las reglas tienen niveles
//! (must/should/avoid/prefer) y una condición opcional que se evalúa contra un
//! contexto numérico (violación = la condición es falsa).

use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Máximo de entradas que devuelve `recall`/`recall_mode` cuando no se pasa un límite
/// explícito. DE-035: antes era un `truncate(20)` fijo y silencioso (footgun para
/// historiales/contadores largos: `length(recall(...))` se topaba en 20). Ahora el
/// límite es configurable por-llamada y el default se subió a 200.
const DEFAULT_RECALL_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleLevel {
    Must,
    Should,
    Avoid,
    Prefer,
}

impl RuleLevel {
    pub fn value(&self) -> &'static str {
        match self {
            RuleLevel::Must => "must",
            RuleLevel::Should => "should",
            RuleLevel::Avoid => "avoid",
            RuleLevel::Prefer => "prefer",
        }
    }
    pub fn parse(s: &str) -> Option<RuleLevel> {
        match s {
            "must" => Some(RuleLevel::Must),
            "should" => Some(RuleLevel::Should),
            "avoid" => Some(RuleLevel::Avoid),
            "prefer" => Some(RuleLevel::Prefer),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryCategory {
    Preference,
    Rule,
    Learning,
    Decision,
    Context,
}

impl MemoryCategory {
    pub fn value(&self) -> &'static str {
        match self {
            MemoryCategory::Preference => "preference",
            MemoryCategory::Rule => "rule",
            MemoryCategory::Learning => "learning",
            MemoryCategory::Decision => "decision",
            MemoryCategory::Context => "context",
        }
    }
    pub fn parse(s: &str) -> Option<MemoryCategory> {
        match s {
            "preference" => Some(MemoryCategory::Preference),
            "rule" => Some(MemoryCategory::Rule),
            "learning" => Some(MemoryCategory::Learning),
            "decision" => Some(MemoryCategory::Decision),
            "context" => Some(MemoryCategory::Context),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: String,
    pub category: MemoryCategory,
    pub content: String,
    #[serde(default)]
    pub data: JsonMap<String, JsonValue>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub created_at: f64,
    #[serde(default)]
    pub updated_at: f64,
    #[serde(default)]
    pub source: String,
    #[serde(default = "one")]
    pub confidence: f64,
    #[serde(default = "yes")]
    pub active: bool,
}

fn one() -> f64 {
    1.0
}
fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerRule {
    pub name: String,
    pub level: RuleLevel,
    pub description: String,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default = "warn_action")]
    pub action: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "yes")]
    pub active: bool,
}

fn warn_action() -> String {
    "warn".to_string()
}

/// Violación de regla (runtime). `Display` espeja el `__str__` del oráculo.
#[derive(Clone, Debug)]
pub struct RuleViolation {
    pub rule: OwnerRule,
    pub detail: String,
}

impl std::fmt::Display for RuleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] Rule '{}' violated: {}. {}",
            self.rule.level.value().to_uppercase(),
            self.rule.name,
            self.rule.description,
            self.detail
        )
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    entries: BTreeMap<String, MemoryEntry>,
    #[serde(default)]
    rules: BTreeMap<String, OwnerRule>,
}

pub struct AgentMemory {
    pub entries: IndexMap<String, MemoryEntry>,
    pub rules: IndexMap<String, OwnerRule>,
    pub violations: Vec<RuleViolation>,
    persist_path: Option<String>,
    counter: u64,
}

impl Default for AgentMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentMemory {
    pub fn new() -> Self {
        Self {
            entries: IndexMap::new(),
            rules: IndexMap::new(),
            violations: Vec::new(),
            persist_path: None,
            counter: 0,
        }
    }
    pub fn with_persist(path: &str) -> Self {
        let mut m = Self::new();
        m.persist_path = Some(path.to_string());
        m
    }

    fn next_id(&mut self) -> String {
        self.counter += 1;
        format!("mem_{}", self.counter)
    }

    /// Sube el piso del contador (tras cargar estado persistido, para no reusar ids).
    pub fn bump_counter(&mut self, n: u64) {
        self.counter = self.counter.max(n);
    }

    pub fn remember(
        &mut self,
        category: &str,
        content: &str,
        data: JsonMap<String, JsonValue>,
        tags: Vec<String>,
        source: &str,
    ) -> Result<String, String> {
        let cat = MemoryCategory::parse(category).ok_or_else(|| {
            format!(
                "Invalid memory category: '{}'. Valid categories: preference, rule, learning, decision, context",
                category
            )
        })?;
        let id = self.next_id();
        let now = now_secs();
        self.entries.insert(
            id.clone(),
            MemoryEntry {
                id: id.clone(),
                category: cat,
                content: content.to_string(),
                data,
                tags,
                created_at: now,
                updated_at: now,
                source: source.to_string(),
                confidence: 1.0,
                active: true,
            },
        );
        self.persist();
        Ok(id)
    }

    /// Recall con semántica OR de tags (compatibilidad). Espeja el oráculo.
    pub fn recall(
        &self,
        category: Option<&str>,
        tags: Option<&[String]>,
        search: Option<&str>,
    ) -> Vec<MemoryEntry> {
        self.recall_mode(category, tags, search, false, None)
    }

    /// Como `recall` pero con modo de tags configurable: `match_all=false` → OR (cualquier
    /// tag, default); `match_all=true` → AND (la entrada debe tener TODOS los tags). El
    /// modo afecta solo a los tags; `category`/`search` estrechan igual. (MF-005)
    pub fn recall_mode(
        &self,
        category: Option<&str>,
        tags: Option<&[String]>,
        search: Option<&str>,
        match_all: bool,
        limit: Option<usize>,
    ) -> Vec<MemoryEntry> {
        let mut results: Vec<MemoryEntry> = self
            .entries
            .values()
            .filter(|e| e.active)
            .filter(|e| category.is_none_or(|c| e.category.value() == c))
            .filter(|e| match tags {
                Some(ts) if match_all => ts.iter().all(|t| e.tags.contains(t)),
                Some(ts) => ts.iter().any(|t| e.tags.contains(t)),
                None => true,
            })
            .filter(|e| match search {
                Some(s) => {
                    let s = s.to_lowercase();
                    e.content.to_lowercase().contains(&s)
                        || e.data.values().any(|v| v.to_string().to_lowercase().contains(&s))
                }
                None => true,
            })
            .cloned()
            .collect();
        // Más-reciente-primero por `updated_at`: `[0]` es la entrada más recientemente
        // escrita/actualizada, `[len-1]` la más vieja. (DE-035: documentado en el skill.)
        results.sort_by(|a, b| b.updated_at.partial_cmp(&a.updated_at).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit.unwrap_or(DEFAULT_RECALL_LIMIT));
        results
    }

    pub fn forget(&mut self, id: &str) {
        if let Some(e) = self.entries.get_mut(id) {
            e.active = false;
            self.persist();
        }
    }

    pub fn update(&mut self, id: &str, content: Option<&str>, data: Option<JsonMap<String, JsonValue>>) {
        if let Some(e) = self.entries.get_mut(id) {
            if let Some(c) = content {
                e.content = c.to_string();
            }
            if let Some(d) = data {
                for (k, v) in d {
                    e.data.insert(k, v);
                }
            }
            e.updated_at = now_secs();
            self.persist();
        }
    }

    pub fn add_rule(&mut self, name: &str, level: &str, description: &str, condition: Option<String>, category: &str) -> Result<(), String> {
        let lvl = RuleLevel::parse(level).ok_or_else(|| format!("Invalid rule level: '{}'", level))?;
        // Auto-extrae la condición de la descripción si no se dio.
        let cond = condition.or_else(|| extract_condition(description));
        self.rules.insert(
            name.to_string(),
            OwnerRule {
                name: name.to_string(),
                level: lvl,
                description: description.to_string(),
                condition: cond,
                action: "warn".to_string(),
                category: category.to_string(),
                tags: Vec::new(),
                active: true,
            },
        );
        self.persist();
        Ok(())
    }

    pub fn check_rules(&mut self, category: Option<&str>, context: &HashMap<String, f64>) -> Vec<RuleViolation> {
        let mut out = Vec::new();
        let rules: Vec<OwnerRule> = self.rules.values().cloned().collect();
        for rule in rules {
            if !rule.active {
                continue;
            }
            if let Some(c) = category {
                if !rule.category.is_empty() && rule.category != c {
                    continue;
                }
            }
            if let Some(cond) = &rule.condition {
                if evaluate_condition(cond, context) {
                    let v = RuleViolation { rule: rule.clone(), detail: format!("Context: {:?}", context) };
                    out.push(v.clone());
                    self.violations.push(v);
                }
            }
        }
        out
    }

    pub fn get_rules(&self, category: Option<&str>, level: Option<&str>) -> Vec<OwnerRule> {
        self.rules
            .values()
            .filter(|r| r.active)
            .filter(|r| category.is_none_or(|c| r.category == c))
            .filter(|r| level.is_none_or(|l| r.level.value() == l))
            .cloned()
            .collect()
    }

    pub fn remove_rule(&mut self, name: &str) {
        if let Some(r) = self.rules.get_mut(name) {
            r.active = false;
            self.persist();
        }
    }

    pub fn format_summary(&self) -> String {
        let active_entries: Vec<&MemoryEntry> = self.entries.values().filter(|e| e.active).collect();
        let active_rules: Vec<&OwnerRule> = self.rules.values().filter(|r| r.active).collect();
        let mut lines = vec![format!(
            "Agent Memory: {} entries, {} rules",
            active_entries.len(),
            active_rules.len()
        )];
        if !active_rules.is_empty() {
            lines.push("  Rules:".to_string());
            for r in &active_rules {
                lines.push(format!("    [{:6}] {}: {}", r.level.value(), r.name, r.description));
            }
        }
        lines.join("\n")
    }

    fn persist(&self) {
        if let Some(path) = &self.persist_path {
            let p = Persisted {
                entries: self.entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                rules: self.rules.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            };
            if let Ok(json) = serde_json::to_string_pretty(&p) {
                let _ = std::fs::write(path, json);
            }
        }
    }

    pub fn load(&mut self) {
        if let Some(path) = &self.persist_path {
            if let Ok(s) = std::fs::read_to_string(path) {
                if let Ok(p) = serde_json::from_str::<Persisted>(&s) {
                    for (k, v) in p.entries {
                        if let Some(n) = k.strip_prefix("mem_").and_then(|n| n.parse::<u64>().ok()) {
                            self.counter = self.counter.max(n);
                        }
                        self.entries.insert(k, v);
                    }
                    for (k, v) in p.rules {
                        self.rules.insert(k, v);
                    }
                }
            }
        }
    }
}

/// Extrae "var op num" de un texto (para auto-condición de reglas).
fn extract_condition(text: &str) -> Option<String> {
    let re = Regex::new(r"(\w+\s*(?:<=|>=|<|>|==|!=)\s*[\d.]+)").ok()?;
    re.captures(text).map(|c| c[1].to_string())
}

/// Evalúa "var op valor" contra el contexto. Devuelve true si la regla está VIOLADA
/// (la condición es falsa).
fn evaluate_condition(condition: &str, context: &HashMap<String, f64>) -> bool {
    let re = match Regex::new(r"^(\w+)\s*(<=|>=|<|>|==|!=)\s*(.+)$") {
        Ok(r) => r,
        Err(_) => return false,
    };
    let caps = match re.captures(condition.trim()) {
        Some(c) => c,
        None => return false,
    };
    let var = &caps[1];
    let op = &caps[2];
    let threshold: f64 = match caps[3].trim().parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let actual = match context.get(var) {
        Some(a) => *a,
        None => return false,
    };
    // La condición describe lo que DEBE ser verdadero. Violación = condición falsa.
    match op {
        "<=" => !(actual <= threshold),
        ">=" => !(actual >= threshold),
        "<" => !(actual < threshold),
        ">" => !(actual > threshold),
        "==" => !(actual == threshold),
        "!=" => !(actual != threshold),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(pairs: &[(&str, f64)]) -> HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }
    fn tags(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn memory_remember_recall() {
        let mut m = AgentMemory::new();
        m.remember("preference", "Formal tone preferred", JsonMap::new(), tags(&["communication"]), "agent").unwrap();
        let r = m.recall(Some("preference"), None, None);
        assert_eq!(r.len(), 1);
        assert!(r[0].content.contains("Formal"));
    }

    #[test]
    fn memory_recall_by_tags() {
        let mut m = AgentMemory::new();
        m.remember("preference", "Use metric units", JsonMap::new(), tags(&["formatting"]), "agent").unwrap();
        m.remember("preference", "Formal tone", JsonMap::new(), tags(&["communication"]), "agent").unwrap();
        let r = m.recall(None, Some(&tags(&["communication"])), None);
        assert_eq!(r.len(), 1);
        assert!(r[0].content.contains("Formal"));
    }

    #[test]
    fn memory_recall_mode_any_vs_all() {
        // MF-005: OR (any, default) vs AND (all) sobre los tags.
        let mut m = AgentMemory::new();
        m.remember("context", "A", JsonMap::new(), tags(&["s1", "turn"]), "agent").unwrap();
        m.remember("context", "B", JsonMap::new(), tags(&["s1", "obj"]), "agent").unwrap();
        // OR: ["s1","obj"] matchea ambas (las dos tienen s1).
        assert_eq!(m.recall(Some("context"), Some(&tags(&["s1", "obj"])), None).len(), 2);
        assert_eq!(m.recall_mode(Some("context"), Some(&tags(&["s1", "obj"])), None, false, None).len(), 2);
        // AND: solo B tiene s1 Y obj.
        let only_b = m.recall_mode(Some("context"), Some(&tags(&["s1", "obj"])), None, true, None);
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_b[0].content, "B");
    }

    #[test]
    fn memory_recall_newest_first() {
        // DE-035: recall ordena más-reciente-primero por `updated_at`: [0] = la más nueva.
        let mut m = AgentMemory::new();
        let id_old = m.remember("context", "T1-viejo", JsonMap::new(), tags(&["o"]), "agent").unwrap();
        let id_mid = m.remember("context", "T2", JsonMap::new(), tags(&["o"]), "agent").unwrap();
        let id_new = m.remember("context", "T3-nuevo", JsonMap::new(), tags(&["o"]), "agent").unwrap();
        // Fijar updated_at explícito → orden determinista (sin depender del reloj).
        m.entries.get_mut(&id_old).unwrap().updated_at = 100.0;
        m.entries.get_mut(&id_mid).unwrap().updated_at = 200.0;
        m.entries.get_mut(&id_new).unwrap().updated_at = 300.0;
        let r = m.recall(Some("context"), Some(&tags(&["o"])), None);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].content, "T3-nuevo"); // más reciente primero
        assert_eq!(r[r.len() - 1].content, "T1-viejo"); // más vieja al final
    }

    #[test]
    fn memory_recall_limit_configurable() {
        // DE-035: el límite es configurable; el default (200) ya no trunca a 20.
        let mut m = AgentMemory::new();
        for i in 0..25 {
            m.remember("context", &format!("entry-{i}"), JsonMap::new(), tags(&["lim"]), "agent").unwrap();
        }
        // Sin límite explícito: las 25 entran bajo el default; antes se truncaba a 20.
        assert_eq!(m.recall_mode(Some("context"), Some(&tags(&["lim"])), None, false, None).len(), 25);
        // Límite explícito menor que el total.
        assert_eq!(m.recall_mode(Some("context"), Some(&tags(&["lim"])), None, false, Some(10)).len(), 10);
        // Límite explícito mayor que el total → devuelve todas.
        assert_eq!(m.recall_mode(Some("context"), Some(&tags(&["lim"])), None, false, Some(100)).len(), 25);
    }

    #[test]
    fn memory_recall_by_search() {
        let mut m = AgentMemory::new();
        m.remember("learning", "API X is slow on Mondays", JsonMap::new(), vec![], "agent").unwrap();
        m.remember("learning", "Customer Y prefers phone calls", JsonMap::new(), vec![], "agent").unwrap();
        let r = m.recall(None, None, Some("slow"));
        assert_eq!(r.len(), 1);
        assert!(r[0].content.contains("API X"));
    }

    #[test]
    fn memory_forget() {
        let mut m = AgentMemory::new();
        let id = m.remember("context", "temp info", JsonMap::new(), vec![], "agent").unwrap();
        m.forget(&id);
        assert_eq!(m.recall(Some("context"), None, None).len(), 0);
    }

    #[test]
    fn memory_update() {
        let mut m = AgentMemory::new();
        let mut data = JsonMap::new();
        data.insert("version".into(), json!(1));
        let id = m.remember("learning", "Initial version", data, vec![], "agent").unwrap();
        let mut d2 = JsonMap::new();
        d2.insert("version".into(), json!(2));
        m.update(&id, Some("Updated version"), Some(d2));
        let r = m.recall(Some("learning"), None, None);
        assert!(r[0].content.contains("Updated"));
        assert_eq!(r[0].data.get("version"), Some(&json!(2)));
    }

    #[test]
    fn memory_persistence() {
        let mut path = std::env::temp_dir();
        path.push("synsema_memory_test.json");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);
        {
            let mut m = AgentMemory::with_persist(&p);
            m.remember("preference", "Dark mode", JsonMap::new(), tags(&["ui"]), "agent").unwrap();
            m.add_rule("no_spam", "must", "Never send unsolicited emails", None, "communication").unwrap();
        }
        let mut m2 = AgentMemory::with_persist(&p);
        m2.load();
        assert_eq!(m2.recall(Some("preference"), None, None).len(), 1);
        assert_eq!(m2.get_rules(None, None).len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rule_add_and_get() {
        let mut m = AgentMemory::new();
        m.add_rule("max_discount", "must", "discount <= 0.20", None, "pricing").unwrap();
        let rules = m.get_rules(Some("pricing"), None);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "max_discount");
        assert_eq!(rules[0].level, RuleLevel::Must);
    }

    #[test]
    fn rule_check_violation() {
        let mut m = AgentMemory::new();
        m.add_rule("max_discount", "must", "discount <= 0.20", None, "pricing").unwrap();
        let v = m.check_rules(Some("pricing"), &ctx(&[("discount", 0.25)]));
        assert_eq!(v.len(), 1);
        assert!(v[0].to_string().contains("max_discount"));
    }

    #[test]
    fn rule_check_pass() {
        let mut m = AgentMemory::new();
        m.add_rule("max_discount", "must", "discount <= 0.20", None, "pricing").unwrap();
        let v = m.check_rules(Some("pricing"), &ctx(&[("discount", 0.15)]));
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn rule_check_multiple() {
        let mut m = AgentMemory::new();
        m.add_rule("max_discount", "must", "discount <= 0.20", None, "pricing").unwrap();
        m.add_rule("min_price", "must", "price >= 10", None, "pricing").unwrap();
        let v = m.check_rules(Some("pricing"), &ctx(&[("discount", 0.25), ("price", 5.0)]));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn rule_remove() {
        let mut m = AgentMemory::new();
        m.add_rule("old_rule", "should", "something", None, "test").unwrap();
        m.remove_rule("old_rule");
        assert_eq!(m.get_rules(None, None).len(), 0);
    }

    #[test]
    fn rule_levels() {
        let mut m = AgentMemory::new();
        m.add_rule("r1", "must", "Hard rule", None, "a").unwrap();
        m.add_rule("r2", "should", "Soft rule", None, "a").unwrap();
        m.add_rule("r3", "avoid", "Avoid this", None, "a").unwrap();
        m.add_rule("r4", "prefer", "Prefer this", None, "a").unwrap();
        assert_eq!(m.get_rules(None, Some("must")).len(), 1);
        assert_eq!(m.get_rules(None, Some("should")).len(), 1);
    }
}

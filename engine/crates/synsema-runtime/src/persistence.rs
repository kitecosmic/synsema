//! StatePersistence cross-run — sobrevive reinicios. Port de
//! `synsema/runtime/persistence.py`.
//!
//! La memoria del agente (entries + rules) y el progreso de tareas se persisten en
//! SQLite. Al re-ejecutar el mismo programa (mismo nombre), se cargan automáticamente.
//! Ruta: `~/.synsema/state/<program_name>.db` (idéntico al oráculo; mismo esquema,
//! así los archivos son intercambiables Python↔Rust).

use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::{Map as JsonMap, Value as JsonValue};

use synsema_agents::memory::{AgentMemory, MemoryCategory, MemoryEntry, OwnerRule, RuleLevel};
use synsema_agents::progress::{ProgressManager, StepStatus, TaskProgress, TaskStep};

fn default_state_path(program_name: &str) -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    let dir = PathBuf::from(home).join(".synsema").join("state");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{}.db", program_name))
}

pub struct StatePersistence {
    conn: Connection,
}

impl StatePersistence {
    /// Abre (o crea) la base para `program_name` bajo `~/.synsema/state/`.
    pub fn open(program_name: &str) -> Result<Self, String> {
        let path = default_state_path(program_name);
        Self::open_path(&path)
    }

    pub fn open_path(path: &std::path::Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("state db open: {}", e))?;
        let p = StatePersistence { conn };
        p.init_db()?;
        Ok(p)
    }

    fn init_db(&self) -> Result<(), String> {
        // Mismo esquema que persistence.py (incluye columnas que Rust no usa, p.ej.
        // progress.metadata, para que los archivos sean compatibles con el oráculo).
        self.conn
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS memory (
                     id TEXT PRIMARY KEY, category TEXT, content TEXT, data TEXT,
                     tags TEXT, source TEXT, confidence REAL, active INTEGER,
                     created_at REAL, updated_at REAL
                 );
                 CREATE TABLE IF NOT EXISTS rules (
                     name TEXT PRIMARY KEY, level TEXT, description TEXT, condition TEXT,
                     action TEXT, category TEXT, tags TEXT, active INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS progress (
                     task_name TEXT, step_name TEXT, status TEXT, started_at REAL,
                     finished_at REAL, result TEXT, error TEXT, metadata TEXT,
                     retries INTEGER, PRIMARY KEY (task_name, step_name)
                 );
                 CREATE TABLE IF NOT EXISTS decisions (
                     id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, error_type TEXT,
                     error_message TEXT, context TEXT, options TEXT, chosen_option TEXT,
                     chosen_label TEXT, outcome TEXT
                 );",
            )
            .map_err(|e| format!("state db init: {}", e))
    }

    pub fn save_from(&self, memory: &AgentMemory, progress: &ProgressManager) {
        self.save_memory(memory);
        self.save_rules(memory);
        self.save_progress(progress);
    }

    pub fn load_into(&self, memory: &mut AgentMemory, progress: &mut ProgressManager) {
        self.load_memory(memory);
        self.load_rules(memory);
        self.load_progress(progress);
    }

    fn save_memory(&self, memory: &AgentMemory) {
        for entry in memory.entries.values() {
            let data = JsonValue::Object(entry.data.clone()).to_string();
            let tags = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());
            let _ = self.conn.execute(
                "INSERT OR REPLACE INTO memory
                 (id, category, content, data, tags, source, confidence, active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    entry.id,
                    entry.category.value(),
                    entry.content,
                    data,
                    tags,
                    entry.source,
                    entry.confidence,
                    entry.active as i64,
                    entry.created_at,
                    entry.updated_at,
                ],
            );
        }
    }

    fn load_memory(&self, memory: &mut AgentMemory) {
        let mut stmt = match self.conn.prepare(
            "SELECT id, category, content, data, tags, source, confidence, active, created_at, updated_at
             FROM memory WHERE active = 1",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<f64>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<f64>>(8)?,
                row.get::<_, Option<f64>>(9)?,
            ))
        });
        let rows = match rows {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut max_counter: u64 = 0;
        for r in rows.flatten() {
            let (id, category, content, data, tags, source, confidence, active, created_at, updated_at) = r;
            let cat = match MemoryCategory::parse(&category) {
                Some(c) => c,
                None => continue,
            };
            let data_map: JsonMap<String, JsonValue> = data
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str::<JsonValue>(s).ok())
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            let tags_vec: Vec<String> = tags
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            // Sigue el contador de ids `mem_<n>` (igual que el oráculo).
            if let Some(n) = id.split('_').nth(1).and_then(|n| n.parse::<u64>().ok()) {
                max_counter = max_counter.max(n);
            }
            memory.entries.insert(
                id.clone(),
                MemoryEntry {
                    id,
                    category: cat,
                    content,
                    data: data_map,
                    tags: tags_vec,
                    created_at: created_at.unwrap_or(0.0),
                    updated_at: updated_at.unwrap_or(0.0),
                    source: source.unwrap_or_default(),
                    confidence: confidence.unwrap_or(1.0),
                    active: active != 0,
                },
            );
        }
        memory.bump_counter(max_counter);
    }

    fn save_rules(&self, memory: &AgentMemory) {
        for rule in memory.rules.values() {
            let tags = serde_json::to_string(&rule.tags).unwrap_or_else(|_| "[]".to_string());
            let _ = self.conn.execute(
                "INSERT OR REPLACE INTO rules
                 (name, level, description, condition, action, category, tags, active)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    rule.name,
                    rule.level.value(),
                    rule.description,
                    rule.condition,
                    rule.action,
                    rule.category,
                    tags,
                    rule.active as i64,
                ],
            );
        }
    }

    fn load_rules(&self, memory: &mut AgentMemory) {
        let mut stmt = match self.conn.prepare(
            "SELECT name, level, description, condition, action, category, tags, active
             FROM rules WHERE active = 1",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        });
        let rows = match rows {
            Ok(r) => r,
            Err(_) => return,
        };
        for r in rows.flatten() {
            let (name, level, description, condition, action, category, tags, active) = r;
            let lvl = match RuleLevel::parse(&level) {
                Some(l) => l,
                None => continue,
            };
            let tags_vec: Vec<String> = tags
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            memory.rules.insert(
                name.clone(),
                OwnerRule {
                    name,
                    level: lvl,
                    description: description.unwrap_or_default(),
                    condition,
                    action: action.unwrap_or_else(|| "warn".to_string()),
                    category: category.unwrap_or_default(),
                    tags: tags_vec,
                    active: active != 0,
                },
            );
        }
    }

    fn save_progress(&self, progress: &ProgressManager) {
        for (task_name, tp) in &progress.tasks {
            for step in &tp.steps {
                let _ = self.conn.execute(
                    "INSERT OR REPLACE INTO progress
                     (task_name, step_name, status, started_at, finished_at, result, error, metadata, retries)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        task_name,
                        step.name,
                        step.status.value(),
                        step.started_at,
                        step.finished_at,
                        step.result,
                        step.error,
                        "{}", // metadata: Rust no la modela; "{}" mantiene el esquema del oráculo
                        step.retries,
                    ],
                );
            }
        }
    }

    fn load_progress(&self, progress: &mut ProgressManager) {
        let task_names: Vec<String> = {
            let mut stmt = match self.conn.prepare("SELECT DISTINCT task_name FROM progress") {
                Ok(s) => s,
                Err(_) => return,
            };
            let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
                Ok(r) => r,
                Err(_) => return,
            };
            rows.flatten().collect()
        };

        for task_name in task_names {
            let mut stmt = match self.conn.prepare(
                "SELECT step_name, status, started_at, finished_at, result, error, retries
                 FROM progress WHERE task_name = ?1 ORDER BY rowid",
            ) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let rows = stmt.query_map(rusqlite::params![task_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<f64>>(2)?,
                    row.get::<_, Option<f64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            });
            let rows = match rows {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut steps = Vec::new();
            for r in rows.flatten() {
                let (step_name, status, started_at, finished_at, result, error, retries) = r;
                steps.push(TaskStep {
                    name: step_name,
                    status: StepStatus::parse(&status).unwrap_or(StepStatus::Pending),
                    started_at,
                    finished_at,
                    result,
                    error,
                    retries: retries.unwrap_or(0),
                });
            }
            progress.tasks.insert(
                task_name.clone(),
                TaskProgress {
                    task_name,
                    steps,
                    created_at: 0.0,
                    agent_name: String::new(),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map as JMap;

    #[test]
    fn roundtrip_memory_rules_progress() {
        let dir = std::env::temp_dir().join("syn_state_persist_test");
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("roundtrip.db");
        let _ = std::fs::remove_file(&db);

        // Escribe estado.
        {
            let p = StatePersistence::open_path(&db).unwrap();
            let mut mem = AgentMemory::new();
            mem.remember("preference", "Dark mode", JMap::new(), vec!["ui".into()], "agent").unwrap();
            mem.add_rule("max_discount", "must", "discount <= 0.20", None, "pricing").unwrap();
            let mut prog = ProgressManager::new();
            prog.create("job", &["a".to_string(), "b".to_string()]);
            prog.start_step("job", "a").unwrap();
            prog.complete_step("job", "a", Some("ok".into())).unwrap();
            p.save_from(&mem, &prog);
        }

        // Reabre y carga.
        let p2 = StatePersistence::open_path(&db).unwrap();
        let mut mem2 = AgentMemory::new();
        let mut prog2 = ProgressManager::new();
        p2.load_into(&mut mem2, &mut prog2);

        assert_eq!(mem2.recall(Some("preference"), None, None).len(), 1);
        assert_eq!(mem2.get_rules(Some("pricing"), None).len(), 1);
        assert!(mem2.recall(Some("preference"), None, None)[0].content.contains("Dark"));
        assert!(prog2.tasks.contains_key("job"));
        assert_eq!(prog2.get_resume_point("job"), Some("b".to_string()));

        // El contador no debe reusar ids: un nuevo remember va a mem_2.
        let new_id = mem2.remember("learning", "x", JMap::new(), vec![], "agent").unwrap();
        assert_eq!(new_id, "mem_2");

        let _ = std::fs::remove_file(&db);
    }
}

//! StatePersistence cross-run — sobrevive reinicios. Port de
//! `synsema/runtime/persistence.py`.
//!
//! La memoria del agente (entries + rules) y el progreso de tareas se persisten en
//! SQLite. La RUTA la resuelve `engine::resolve_declared_state` (DB-M1): la identidad
//! es la memoria DECLARADA — `<dir-del-programa>/.synsema/state/<nombre>.db`, donde
//! `<nombre>` es el de `require memory("<nombre>")`. `SYNSEMA_STATE_DIR` relocaliza el
//! dir; `SYNSEMA_STATE_NAME` quedó deprecado (se ignora con warning); fallback al dir
//! global `~/.synsema/state` si el project-local no es escribible. Sin declaración NO
//! hay persistencia (G-1). El esquema sigue siendo el del oráculo (G-5: archivos
//! intercambiables Python↔Rust; migrar identidad = renombrar el archivo).

use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::{Map as JsonMap, Value as JsonValue};

use synsema_agents::memory::{AgentMemory, MemoryCategory, MemoryEntry, OwnerRule, RuleLevel};
use synsema_agents::progress::{ProgressManager, StepStatus, TaskProgress, TaskStep};

/// Dir de estado GLOBAL del lenguaje (`~/.synsema/state`). Comportamiento histórico,
/// hoy usado como fallback (DE-031) y vía `SYNSEMA_STATE_DIR=~/.synsema/state`.
pub(crate) fn home_state_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    PathBuf::from(home).join(".synsema").join("state")
}

fn default_state_path(program_name: &str) -> PathBuf {
    let dir = home_state_dir();
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{}.db", program_name))
}

pub struct StatePersistence {
    conn: Connection,
    /// Ronda 5 (B1): la última versión de cada fila que este proceso leyó o guardó. Se escribe sólo
    /// lo que cambió: con padre e hijo de `run_program` sobre la misma base, cada uno guardaba TODO
    /// desde su foto y pisaba lo del otro (un `forget` del padre revivía al guardar el hijo).
    seen: std::cell::RefCell<std::collections::HashMap<String, String>>,
    /// Ronda 6 (B1): un guardado que falla avisa una vez por racha de fallas (antes era silencioso).
    warned: std::cell::Cell<bool>,
}

impl StatePersistence {
    /// Abre (o crea) la base para `program_name` bajo `~/.synsema/state/`.
    pub fn open(program_name: &str) -> Result<Self, String> {
        let path = default_state_path(program_name);
        Self::open_path(&path)
    }

    pub fn open_path(path: &std::path::Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("state db open: {}", e))?;
        // Ronda 4 (revisión, H5): el padre y un hijo de `run_program` pueden abrir la misma base;
        // con espera, una escritura concurrente no se pierde por `SQLITE_BUSY`.
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        let p = StatePersistence { conn, seen: Default::default(), warned: Default::default() };
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

    /// Persiste SOLO memoria + reglas (no toca la tabla de progress). Para el `on_write`
    /// de memoria bajo `serve`: cada `remember`/`forget` no debe pisar el progress
    /// persistido (cada store tiene su propio callback que escribe su propia tabla).
    pub fn save_memory_only(&self, memory: &AgentMemory) {
        self.save_memory(memory);
        self.save_rules(memory);
    }

    /// Persiste SOLO el progress (no toca memoria/reglas). Gemelo de `save_memory_only`
    /// para el `on_write` de progress bajo `serve` (DE-028).
    pub fn save_progress_only(&self, progress: &ProgressManager) {
        self.save_progress(progress);
    }

    /// Ronda 5 (B1): trae a `memory` lo que otro proceso (el hijo de `run_program`) guardó en la
    /// misma base. Cada proceso escribe sólo las filas que cambió (`seen`), así que lo que hay en la
    /// base y difiere de lo que este proceso tiene es del otro: las filas activas pisan la entrada
    /// de su id; una olvidada (`active = 0`) sólo apaga la entrada que ya estaba (el historial
    /// olvidado no se carga). El contador sube con todos los ids.
    /// Ronda 6 (B1): primero se guarda lo propio pendiente, y una entrada propia que no llegó al
    /// disco (un guardado que falló) no se pisa con la de la base: se reintenta en el próximo guardado.
    pub fn reload_memory(&self, memory: &mut AgentMemory) {
        self.save_memory(memory);
        self.save_rules(memory);
        self.read_memory(memory, true);
        self.read_rules(memory, true);
    }

    /// Ronda 5 (B1): el gemelo de `reload_memory` para el progress: los pasos de cada task vienen de
    /// la base; lo demás de la task (cuándo se creó, de qué agente) queda.
    pub fn reload_progress(&self, progress: &mut ProgressManager) {
        self.save_progress(progress);
        self.read_progress(progress, true);
    }

    /// ¿Lo que este proceso tiene en memoria para `key` (`mine`) es un cambio que no llegó al disco?
    fn unsaved(&self, key: &str, mine: Option<String>) -> bool {
        mine.is_some_and(|sig| self.changed(key, &sig))
    }

    /// ¿La fila `key` cambió desde la última vez que este proceso la leyó o la guardó?
    fn changed(&self, key: &str, sig: &str) -> bool {
        self.seen.borrow().get(key).map(String::as_str) != Some(sig)
    }

    fn mark(&self, key: String, sig: String) {
        self.seen.borrow_mut().insert(key, sig);
    }

    /// Marca la fila si se guardó; si no, avisa (una vez por racha de fallas) y queda para el próximo guardado.
    fn saved(&self, r: rusqlite::Result<usize>, key: String, sig: String) {
        match r {
            Ok(_) => {
                // Ronda 7 (N1): una falla nueva después de que todo anduvo vuelve a avisar (en
                // `serve` la base vive lo que el proceso).
                self.warned.set(false);
                self.mark(key, sig)
            }
            Err(e) => {
                if !self.warned.replace(true) {
                    eprintln!(
                        "synsema: warning: could not save to the state db ({}): the change stays in memory and is retried on the next write",
                        e
                    );
                }
            }
        }
    }

    /// Ronda 6 (A1): upsert que CONSERVA el rowid. `INSERT OR REPLACE` borra la fila y la vuelve a
    /// crear al final, y con escrituras sólo de lo cambiado el orden de los pasos (que se lee por
    /// rowid) pasaba a ser el de la última modificación: `resume_point` retomaba por otro paso.

    fn save_memory(&self, memory: &AgentMemory) {
        for entry in memory.entries.values() {
            let (key, sig) = (mem_key(&entry.id), mem_sig(entry));
            if !self.changed(&key, &sig) {
                continue;
            }
            let data = JsonValue::Object(entry.data.clone()).to_string();
            let tags = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());
            let r = self.conn.execute(
                "INSERT INTO memory
                 (id, category, content, data, tags, source, confidence, active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET category = excluded.category, content = excluded.content,
                 data = excluded.data, tags = excluded.tags, source = excluded.source,
                 confidence = excluded.confidence, active = excluded.active,
                 created_at = excluded.created_at, updated_at = excluded.updated_at",
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
            self.saved(r, key, sig);
        }
    }

    fn load_memory(&self, memory: &mut AgentMemory) {
        self.read_memory(memory, false);
    }

    /// `reload`: todas las filas (ver `reload_memory`); si no, sólo las activas (la carga inicial).
    fn read_memory(&self, memory: &mut AgentMemory, reload: bool) {
        let mut stmt = match self.conn.prepare(if reload {
            "SELECT id, category, content, data, tags, source, confidence, active, created_at, updated_at
             FROM memory"
        } else {
            "SELECT id, category, content, data, tags, source, confidence, active, created_at, updated_at
             FROM memory WHERE active = 1"
        }) {
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
            // Sigue el contador de ids `mem_<n>` (igual que el oráculo; también `mem_<n>_<proceso>`).
            if let Some(n) = id.split('_').nth(1).and_then(|n| n.parse::<u64>().ok()) {
                max_counter = max_counter.max(n);
            }
            if active == 0 && !memory.entries.contains_key(&id) {
                continue;
            }
            if reload && self.unsaved(&mem_key(&id), memory.entries.get(&id).map(mem_sig)) {
                continue;
            }
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
            let entry = MemoryEntry {
                id: id.clone(),
                category: cat,
                content,
                data: data_map,
                tags: tags_vec,
                created_at: created_at.unwrap_or(0.0),
                updated_at: updated_at.unwrap_or(0.0),
                source: source.unwrap_or_default(),
                confidence: confidence.unwrap_or(1.0),
                active: active != 0,
            };
            self.mark(mem_key(&id), mem_sig(&entry));
            memory.entries.insert(id, entry);
        }
        memory.bump_counter(max_counter);
    }

    fn save_rules(&self, memory: &AgentMemory) {
        for rule in memory.rules.values() {
            let (key, sig) = (rule_key(&rule.name), rule_sig(rule));
            if !self.changed(&key, &sig) {
                continue;
            }
            let tags = serde_json::to_string(&rule.tags).unwrap_or_else(|_| "[]".to_string());
            let r = self.conn.execute(
                "INSERT INTO rules
                 (name, level, description, condition, action, category, tags, active)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(name) DO UPDATE SET level = excluded.level, description = excluded.description,
                 condition = excluded.condition, action = excluded.action, category = excluded.category,
                 tags = excluded.tags, active = excluded.active",
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
            self.saved(r, key, sig);
        }
    }

    fn load_rules(&self, memory: &mut AgentMemory) {
        self.read_rules(memory, false);
    }

    fn read_rules(&self, memory: &mut AgentMemory, reload: bool) {
        let mut stmt = match self.conn.prepare(if reload {
            "SELECT name, level, description, condition, action, category, tags, active
             FROM rules"
        } else {
            "SELECT name, level, description, condition, action, category, tags, active
             FROM rules WHERE active = 1"
        }) {
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
            if active == 0 && !memory.rules.contains_key(&name) {
                continue;
            }
            if reload && self.unsaved(&rule_key(&name), memory.rules.get(&name).map(rule_sig)) {
                continue;
            }
            let lvl = match RuleLevel::parse(&level) {
                Some(l) => l,
                None => continue,
            };
            let tags_vec: Vec<String> = tags
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let rule = OwnerRule {
                name: name.clone(),
                level: lvl,
                description: description.unwrap_or_default(),
                condition,
                action: action.unwrap_or_else(|| "warn".to_string()),
                category: category.unwrap_or_default(),
                tags: tags_vec,
                active: active != 0,
            };
            self.mark(rule_key(&name), rule_sig(&rule));
            memory.rules.insert(name, rule);
        }
    }

    fn save_progress(&self, progress: &ProgressManager) {
        for (task_name, tp) in &progress.tasks {
            for step in &tp.steps {
                let (key, sig) = (step_key(task_name, &step.name), step_sig(step));
                if !self.changed(&key, &sig) {
                    continue;
                }
                let r = self.conn.execute(
                    "INSERT INTO progress
                     (task_name, step_name, status, started_at, finished_at, result, error, metadata, retries)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(task_name, step_name) DO UPDATE SET status = excluded.status,
                     started_at = excluded.started_at, finished_at = excluded.finished_at,
                     result = excluded.result, error = excluded.error, metadata = excluded.metadata,
                     retries = excluded.retries",
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
                self.saved(r, key, sig);
            }
        }
    }

    fn load_progress(&self, progress: &mut ProgressManager) {
        self.read_progress(progress, false);
    }

    /// `reload`: una task que ya está conserva sus datos propios y toma los pasos de la base.
    fn read_progress(&self, progress: &mut ProgressManager, reload: bool) {
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
                let step = TaskStep {
                    name: step_name,
                    status: StepStatus::parse(&status).unwrap_or(StepStatus::Pending),
                    started_at,
                    finished_at,
                    result,
                    error,
                    retries: retries.unwrap_or(0),
                };
                steps.push(step);
            }
            // Ronda 6 (B1): una task con un paso propio sin guardar queda como está en memoria.
            if let Some(tp) = progress.tasks.get(&task_name) {
                if reload && tp.steps.iter().any(|s| self.unsaved(&step_key(&task_name, &s.name), Some(step_sig(s)))) {
                    continue;
                }
            }
            for s in &steps {
                self.mark(step_key(&task_name, &s.name), step_sig(s));
            }
            match progress.tasks.get_mut(&task_name) {
                Some(tp) if reload => tp.steps = steps,
                _ => {
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
    }
}

// Ronda 5 (B1): la firma de cada fila, para escribir sólo lo que este proceso cambió.
fn mem_key(id: &str) -> String {
    format!("m\u{0}{}", id)
}

fn mem_sig(e: &MemoryEntry) -> String {
    serde_json::json!([
        e.category.value(),
        e.content,
        e.data,
        e.tags,
        e.source,
        e.confidence,
        e.active,
        e.created_at,
        e.updated_at
    ])
    .to_string()
}

fn rule_key(name: &str) -> String {
    format!("r\u{0}{}", name)
}

fn rule_sig(r: &OwnerRule) -> String {
    serde_json::json!([r.level.value(), r.description, r.condition, r.action, r.category, r.tags, r.active]).to_string()
}

fn step_key(task: &str, step: &str) -> String {
    format!("p\u{0}{}\u{0}{}", task, step)
}

fn step_sig(s: &TaskStep) -> String {
    serde_json::json!([s.status.value(), s.started_at, s.finished_at, s.result, s.error, s.retries]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map as JMap;

    /// Ronda 5 (B1): padre e hijo sobre la misma base. Mientras el hijo corre, el padre olvida una
    /// entrada y crea otra; el hijo guarda la suya. Cada uno escribe sólo lo que cambió (el hijo no
    /// revive lo olvidado) y los ids del hijo llevan su marca (no pisa la entrada nueva del padre).
    #[test]
    fn parent_and_child_writing_the_same_base_do_not_undo_each_other() {
        let dir = std::env::temp_dir().join(format!("syn_state_concurrent_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("m.db");
        let _ = std::fs::remove_file(&db);
        let parent = StatePersistence::open_path(&db).unwrap();
        let (mut pm, mut pp) = (AgentMemory::new(), ProgressManager::new());
        parent.load_into(&mut pm, &mut pp);
        let a = pm.remember("learning", "a", JMap::new(), vec![], "main").unwrap();
        parent.save_memory_only(&pm);

        let child = StatePersistence::open_path(&db).unwrap();
        let (mut cm, mut cp) = (AgentMemory::new(), ProgressManager::new());
        child.load_into(&mut cm, &mut cp);
        cm.set_id_tag("c".to_string());

        pm.forget(&a);
        parent.save_memory_only(&pm);
        let b = pm.remember("learning", "del padre", JMap::new(), vec![], "main").unwrap();
        parent.save_memory_only(&pm);
        let c = cm.remember("learning", "del hijo", JMap::new(), vec![], "main").unwrap();
        child.save_memory_only(&cm);
        assert_ne!(b, c);

        parent.reload_memory(&mut pm);
        assert!(!pm.entries[&a].active, "lo olvidado sigue olvidado");
        assert_eq!(pm.entries[&b].content, "del padre");
        assert_eq!(pm.entries[&c].content, "del hijo");
        let fresh = StatePersistence::open_path(&db).unwrap();
        let (mut fm, mut fp) = (AgentMemory::new(), ProgressManager::new());
        fresh.load_into(&mut fm, &mut fp);
        assert_eq!(fm.entries.len(), 2, "en disco: la del padre y la del hijo, la olvidada no");
    }

    /// Ronda 6 (A1): guardar sólo lo cambiado no desordena los pasos (con `INSERT OR REPLACE` la
    /// fila tocada pasaba al final y, al reabrir, `resume_point` retomaba por `b` en vez de `a`).
    #[test]
    fn saving_only_what_changed_keeps_the_order_of_the_steps() {
        let dir = std::env::temp_dir().join(format!("syn_state_order_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("o.db");
        let _ = std::fs::remove_file(&db);
        let p = StatePersistence::open_path(&db).unwrap();
        let (mut m, mut g) = (AgentMemory::new(), ProgressManager::new());
        p.load_into(&mut m, &mut g);
        g.create("job", &["a".to_string(), "b".to_string(), "c".to_string()]);
        p.save_progress_only(&g);
        g.fail_step("job", "b", Some("x".into())).unwrap();
        p.save_progress_only(&g);
        g.fail_step("job", "a", Some("y".into())).unwrap();
        p.save_progress_only(&g);
        let first = m.remember("learning", "uno", JMap::new(), vec![], "main").unwrap();
        m.remember("learning", "dos", JMap::new(), vec![], "main").unwrap();
        p.save_memory_only(&m);
        m.forget(&first);
        p.save_memory_only(&m);

        let q = StatePersistence::open_path(&db).unwrap();
        let (mut m2, mut g2) = (AgentMemory::new(), ProgressManager::new());
        q.load_into(&mut m2, &mut g2);
        let names: Vec<&str> = g2.tasks["job"].steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(g2.get_resume_point("job"), Some("a".to_string()));
        // Y en la misma corrida, tras una recarga.
        q.reload_progress(&mut g2);
        assert_eq!(g2.get_resume_point("job"), Some("a".to_string()));
    }

    /// Ronda 6 (B1): una recarga no pisa un cambio propio que todavía no llegó al disco.
    #[test]
    fn a_reload_keeps_an_unsaved_change_of_this_process() {
        let dir = std::env::temp_dir().join(format!("syn_state_unsaved_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("u.db");
        let _ = std::fs::remove_file(&db);
        let p = StatePersistence::open_path(&db).unwrap();
        let (mut m, mut g) = (AgentMemory::new(), ProgressManager::new());
        p.load_into(&mut m, &mut g);
        let a = m.remember("learning", "a", JMap::new(), vec![], "main").unwrap();
        p.save_memory_only(&m);
        m.forget(&a); // sin guardar
        p.reload_memory(&mut m);
        assert!(!m.entries[&a].active, "el olvido propio sigue");
        let q = StatePersistence::open_path(&db).unwrap();
        let (mut m2, mut g2) = (AgentMemory::new(), ProgressManager::new());
        q.load_into(&mut m2, &mut g2);
        assert!(m2.entries.is_empty(), "y llegó al disco");
    }

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

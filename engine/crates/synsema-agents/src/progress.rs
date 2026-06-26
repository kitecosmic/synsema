//! Seguimiento de progreso de tareas. Port de `synsema/agents/progress.py`.
//!
//! Estructuras puras (sin hilos), con persistencia JSON para resumir tras crash.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    InProgress,
    Done,
    Failed,
    Skipped,
}

impl StepStatus {
    /// String estable (espeja `StepStatus.value` del oráculo) para persistencia.
    pub fn value(&self) -> &'static str {
        match self {
            StepStatus::Pending => "pending",
            StepStatus::InProgress => "in_progress",
            StepStatus::Done => "done",
            StepStatus::Failed => "failed",
            StepStatus::Skipped => "skipped",
        }
    }
    pub fn parse(s: &str) -> Option<StepStatus> {
        match s {
            "pending" => Some(StepStatus::Pending),
            "in_progress" => Some(StepStatus::InProgress),
            "done" => Some(StepStatus::Done),
            "failed" => Some(StepStatus::Failed),
            "skipped" => Some(StepStatus::Skipped),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskStep {
    pub name: String,
    pub status: StepStatus,
    #[serde(default)]
    pub started_at: Option<f64>,
    #[serde(default)]
    pub finished_at: Option<f64>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub retries: i64,
}

impl TaskStep {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: StepStatus::Pending,
            started_at: None,
            finished_at: None,
            result: None,
            error: None,
            retries: 0,
        }
    }
    fn start(&mut self) {
        self.status = StepStatus::InProgress;
        self.started_at = Some(now_secs());
    }
    fn complete(&mut self, result: Option<String>) {
        self.status = StepStatus::Done;
        self.finished_at = Some(now_secs());
        self.result = result;
    }
    fn fail(&mut self, error: Option<String>) {
        self.status = StepStatus::Failed;
        self.finished_at = Some(now_secs());
        self.error = error;
    }
    fn duration_ms(&self) -> Option<f64> {
        match (self.started_at, self.finished_at) {
            (Some(s), Some(f)) => Some((f - s) * 1000.0),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskProgress {
    pub task_name: String,
    pub steps: Vec<TaskStep>,
    #[serde(default)]
    pub created_at: f64,
    #[serde(default)]
    pub agent_name: String,
}

impl TaskProgress {
    fn new(task_name: &str) -> Self {
        Self {
            task_name: task_name.to_string(),
            steps: Vec::new(),
            created_at: now_secs(),
            agent_name: String::new(),
        }
    }

    pub fn get_step(&self, name: &str) -> Option<&TaskStep> {
        self.steps.iter().find(|s| s.name == name)
    }
    fn get_step_mut(&mut self, name: &str) -> Option<&mut TaskStep> {
        self.steps.iter_mut().find(|s| s.name == name)
    }

    pub fn current_step(&self) -> Option<&TaskStep> {
        self.steps.iter().find(|s| s.status == StepStatus::InProgress)
    }

    fn next_pending(&self) -> Option<&TaskStep> {
        self.steps.iter().find(|s| s.status == StepStatus::Pending)
    }

    /// Dónde retomar: paso IN_PROGRESS o FAILED (reintenta), si no el próximo PENDING.
    pub fn resume_point(&self) -> Option<&TaskStep> {
        for s in &self.steps {
            if s.status == StepStatus::InProgress || s.status == StepStatus::Failed {
                return Some(s);
            }
        }
        self.next_pending()
    }

    pub fn is_complete(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.status, StepStatus::Done | StepStatus::Skipped))
    }

    pub fn progress_percent(&self) -> f64 {
        if self.steps.is_empty() {
            return 100.0;
        }
        let done = self
            .steps
            .iter()
            .filter(|s| matches!(s.status, StepStatus::Done | StepStatus::Skipped))
            .count();
        (done as f64 / self.steps.len() as f64) * 100.0
    }

    pub fn format_display(&self) -> String {
        let mut lines = vec![format!("Task: {} ({:.0}%)", self.task_name, self.progress_percent())];
        for step in &self.steps {
            let icon = match step.status {
                StepStatus::Pending => "  ",
                StepStatus::InProgress => ">>",
                StepStatus::Done => "OK",
                StepStatus::Failed => "XX",
                StepStatus::Skipped => "--",
            };
            let dur = match step.duration_ms() {
                Some(d) if d != 0.0 => format!(" ({:.0}ms)", d),
                _ => String::new(),
            };
            let res = match &step.result {
                Some(r) => format!(" \u{2192} {}", r),
                None => String::new(),
            };
            let err = match &step.error {
                Some(e) => format!(" ERROR: {}", e),
                None => String::new(),
            };
            lines.push(format!("  [{}] {}{}{}{}", icon, step.name, dur, res, err));
        }
        lines.join("\n")
    }
}

pub struct ProgressManager {
    pub tasks: IndexMap<String, TaskProgress>,
    persist_path: Option<String>,
}

impl Default for ProgressManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressManager {
    pub fn new() -> Self {
        Self { tasks: IndexMap::new(), persist_path: None }
    }
    pub fn with_persist(path: &str) -> Self {
        Self { tasks: IndexMap::new(), persist_path: Some(path.to_string()) }
    }

    pub fn create(&mut self, task_name: &str, step_names: &[String]) {
        if let Some(existing) = self.tasks.get(task_name) {
            if !existing.is_complete() {
                return; // resume existente
            }
        }
        let mut tp = TaskProgress::new(task_name);
        for n in step_names {
            tp.steps.push(TaskStep::new(n));
        }
        self.tasks.insert(task_name.to_string(), tp);
        self.persist();
    }

    pub fn start_step(&mut self, task_name: &str, step_name: &str) -> Result<(), String> {
        self.with_step(task_name, step_name, |s| s.start())
    }
    pub fn complete_step(&mut self, task_name: &str, step_name: &str, result: Option<String>) -> Result<(), String> {
        self.with_step(task_name, step_name, |s| s.complete(result.clone()))
    }
    pub fn fail_step(&mut self, task_name: &str, step_name: &str, error: Option<String>) -> Result<(), String> {
        self.with_step(task_name, step_name, |s| s.fail(error.clone()))
    }

    fn with_step<F: FnMut(&mut TaskStep)>(&mut self, task_name: &str, step_name: &str, mut f: F) -> Result<(), String> {
        let tp = self.tasks.get_mut(task_name).ok_or_else(|| format!("No task '{}' tracked", task_name))?;
        let step = tp
            .get_step_mut(step_name)
            .ok_or_else(|| format!("No step '{}' in task '{}'", step_name, task_name))?;
        f(step);
        self.persist();
        Ok(())
    }

    pub fn get_resume_point(&self, task_name: &str) -> Option<String> {
        self.tasks.get(task_name).and_then(|tp| tp.resume_point().map(|s| s.name.clone()))
    }

    fn persist(&self) {
        if let Some(path) = &self.persist_path {
            let map: BTreeMap<&String, &TaskProgress> = self.tasks.iter().collect();
            if let Ok(json) = serde_json::to_string_pretty(&map) {
                let _ = std::fs::write(path, json);
            }
        }
    }

    pub fn load(&mut self) {
        if let Some(path) = &self.persist_path {
            if let Ok(s) = std::fs::read_to_string(path) {
                if let Ok(map) = serde_json::from_str::<BTreeMap<String, TaskProgress>>(&s) {
                    for (k, v) in map {
                        self.tasks.insert(k, v);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn progress_create() {
        let mut mgr = ProgressManager::new();
        mgr.create("job1", &steps(&["fetch", "process", "save"]));
        assert_eq!(mgr.tasks["job1"].steps.len(), 3);
        assert_eq!(mgr.tasks["job1"].progress_percent(), 0.0);
    }

    #[test]
    fn progress_step_lifecycle() {
        let mut mgr = ProgressManager::new();
        mgr.create("job", &steps(&["a", "b", "c"]));
        mgr.start_step("job", "a").unwrap();
        assert_eq!(mgr.tasks["job"].current_step().unwrap().name, "a");
        mgr.complete_step("job", "a", Some("done!".into())).unwrap();
        assert_eq!(mgr.tasks["job"].steps[0].status, StepStatus::Done);
        assert!((mgr.tasks["job"].progress_percent() - 33.33).abs() < 1.0);
    }

    #[test]
    fn progress_resume_point() {
        let mut mgr = ProgressManager::new();
        mgr.create("job", &steps(&["a", "b", "c"]));
        mgr.start_step("job", "a").unwrap();
        mgr.complete_step("job", "a", None).unwrap();
        assert_eq!(mgr.get_resume_point("job"), Some("b".to_string()));
    }

    #[test]
    fn progress_resume_after_failure() {
        let mut mgr = ProgressManager::new();
        mgr.create("job", &steps(&["a", "b", "c"]));
        mgr.start_step("job", "a").unwrap();
        mgr.complete_step("job", "a", None).unwrap();
        mgr.start_step("job", "b").unwrap();
        mgr.fail_step("job", "b", Some("connection lost".into())).unwrap();
        assert_eq!(mgr.get_resume_point("job"), Some("b".to_string()));
    }

    #[test]
    fn progress_resume_mid_step() {
        let mut mgr = ProgressManager::new();
        mgr.create("job", &steps(&["a", "b", "c"]));
        mgr.start_step("job", "a").unwrap();
        assert_eq!(mgr.get_resume_point("job"), Some("a".to_string()));
    }

    #[test]
    fn progress_complete() {
        let mut mgr = ProgressManager::new();
        mgr.create("job", &steps(&["a", "b"]));
        mgr.start_step("job", "a").unwrap();
        mgr.complete_step("job", "a", None).unwrap();
        mgr.start_step("job", "b").unwrap();
        mgr.complete_step("job", "b", None).unwrap();
        assert!(mgr.tasks["job"].is_complete());
        assert_eq!(mgr.tasks["job"].progress_percent(), 100.0);
    }

    #[test]
    fn progress_display() {
        let mut mgr = ProgressManager::new();
        mgr.create("sync", &steps(&["fetch", "validate", "update"]));
        mgr.start_step("sync", "fetch").unwrap();
        mgr.complete_step("sync", "fetch", Some("100 items".into())).unwrap();
        mgr.start_step("sync", "validate").unwrap();
        let display = mgr.tasks["sync"].format_display();
        assert!(display.contains("OK"));
        assert!(display.contains(">>"));
        assert!(display.contains("100 items"));
    }

    #[test]
    fn progress_persistence() {
        let mut path = std::env::temp_dir();
        path.push("synsema_progress_test.json");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);
        {
            let mut mgr = ProgressManager::with_persist(&p);
            mgr.create("job", &steps(&["a", "b"]));
            mgr.start_step("job", "a").unwrap();
            mgr.complete_step("job", "a", None).unwrap();
        }
        let mut mgr2 = ProgressManager::with_persist(&p);
        mgr2.load();
        assert!(mgr2.tasks.contains_key("job"));
        assert_eq!(mgr2.tasks["job"].steps[0].status, StepStatus::Done);
        assert_eq!(mgr2.get_resume_point("job"), Some("b".to_string()));
        let _ = std::fs::remove_file(&path);
    }
}

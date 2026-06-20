//! Ejecución especulativa — runtime reversible. Port de
//! `syntecnia/runtime/speculative.py`.
//!
//! Permite forkear el estado, probar enfoques, hacer rollback si algo falla, y
//! comparar resultados antes de commitear (como una transacción o branch de git):
//! snapshot del entorno → ejecutar especulativamente → rollback (restaura) /
//! commit (descarta) / fork (N branches independientes) + choose_and_apply.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use indexmap::IndexMap;

use syntecnia_core::interpreter::Environment;
use syntecnia_core::types::SynValue;

/// Copia profunda de un valor (list/map → nuevos Rc; el resto clona). Espeja el
/// `deepcopy` de Python (con fallback a clonar tasks/builtins).
fn deep_copy(v: &SynValue) -> SynValue {
    match v {
        SynValue::List(l) => {
            SynValue::List(Rc::new(RefCell::new(l.borrow().iter().map(deep_copy).collect())))
        }
        SynValue::Map(m) => {
            let mut nm = IndexMap::new();
            for (k, val) in m.borrow().iter() {
                nm.insert(k.clone(), deep_copy(val));
            }
            SynValue::Map(Rc::new(RefCell::new(nm)))
        }
        other => other.clone(),
    }
}

/// Snapshot congelado de un entorno (para rollback).
pub struct EnvironmentSnapshot {
    pub name: String,
    bindings: HashMap<String, SynValue>,
    parent_snapshot: Option<Box<EnvironmentSnapshot>>,
}

impl EnvironmentSnapshot {
    pub fn new(env: &Rc<RefCell<Environment>>) -> Self {
        let e = env.borrow();
        let bindings = e.bindings.iter().map(|(k, v)| (k.clone(), deep_copy(v))).collect();
        let parent_snapshot = e.parent.as_ref().map(|p| Box::new(EnvironmentSnapshot::new(p)));
        EnvironmentSnapshot { name: e.name.clone(), bindings, parent_snapshot }
    }

    pub fn restore(&self, env: &Rc<RefCell<Environment>>) {
        {
            let mut e = env.borrow_mut();
            e.bindings.clear();
            for (k, v) in &self.bindings {
                e.bindings.insert(k.clone(), deep_copy(v));
            }
        }
        let parent = env.borrow().parent.clone();
        if let (Some(ps), Some(p)) = (&self.parent_snapshot, parent) {
            ps.restore(&p);
        }
    }
}

/// Contexto especulativo: estado antes de la especulación + commit/rollback.
pub struct SpeculativeContext {
    pub name: String,
    snapshot: EnvironmentSnapshot,
    env: Rc<RefCell<Environment>>,
    pub committed: bool,
    pub rolled_back: bool,
}

/// Closure de una rama de `fork`: corre sobre el entorno de la rama → resultado.
pub type BranchFn = Box<dyn Fn(&Rc<RefCell<Environment>>) -> SynValue>;

#[derive(Default)]
pub struct SpeculativeEngine {
    active: usize,
}

impl SpeculativeEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin(&mut self, env: &Rc<RefCell<Environment>>, name: &str) -> SpeculativeContext {
        self.active += 1;
        SpeculativeContext {
            name: name.to_string(),
            snapshot: EnvironmentSnapshot::new(env),
            env: env.clone(),
            committed: false,
            rolled_back: false,
        }
    }

    pub fn rollback(&mut self, ctx: &mut SpeculativeContext) {
        if ctx.committed {
            return; // no rollback tras commit
        }
        ctx.snapshot.restore(&ctx.env);
        ctx.rolled_back = true;
        self.active = self.active.saturating_sub(1);
    }

    pub fn commit(&mut self, ctx: &mut SpeculativeContext) {
        if ctx.rolled_back {
            return;
        }
        ctx.committed = true;
        self.active = self.active.saturating_sub(1);
    }

    /// Forkea en múltiples ramas independientes (cada una con copia del entorno).
    /// Devuelve (resultado, estado_final) por rama.
    pub fn fork(
        &mut self,
        env: &Rc<RefCell<Environment>>,
        branches: Vec<BranchFn>,
    ) -> Vec<(SynValue, EnvironmentSnapshot)> {
        let mut results = Vec::new();
        let parent = env.borrow().parent.clone();
        for (i, branch_fn) in branches.into_iter().enumerate() {
            let branch_env = match &parent {
                Some(p) => Environment::child(p, &format!("fork:{}", i)),
                None => Environment::root(&format!("fork:{}", i)),
            };
            {
                let mut be = branch_env.borrow_mut();
                for (k, v) in env.borrow().bindings.iter() {
                    be.bindings.insert(k.clone(), deep_copy(v));
                }
            }
            let result = branch_fn(&branch_env);
            let final_state = EnvironmentSnapshot::new(&branch_env);
            results.push((result, final_state));
        }
        results
    }

    /// Tras forkear, elige una rama y aplica su estado final al entorno real.
    pub fn choose_and_apply(
        &mut self,
        env: &Rc<RefCell<Environment>>,
        results: &[(SynValue, EnvironmentSnapshot)],
        index: usize,
    ) {
        if let Some((_, snapshot)) = results.get(index) {
            snapshot.restore(env);
        }
    }

    pub fn is_speculating(&self) -> bool {
        self.active > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syntecnia_core::types::{syn_int, syn_text};

    fn env_get_int(env: &Rc<RefCell<Environment>>, key: &str) -> Option<i64> {
        match env.borrow().bindings.get(key) {
            Some(SynValue::Number(syntecnia_core::number::Number::Int(i))) => Some(*i),
            _ => None,
        }
    }
    fn env_set(env: &Rc<RefCell<Environment>>, key: &str, v: SynValue) {
        env.borrow_mut().bindings.insert(key.to_string(), v);
    }

    #[test]
    fn rollback() {
        let env = Environment::root("global");
        env_set(&env, "x", syn_int(10));
        let mut spec = SpeculativeEngine::new();
        let mut ctx = spec.begin(&env, "test");
        env_set(&env, "x", syn_int(999));
        assert_eq!(env_get_int(&env, "x"), Some(999));
        spec.rollback(&mut ctx);
        assert_eq!(env_get_int(&env, "x"), Some(10));
    }

    #[test]
    fn commit() {
        let env = Environment::root("global");
        env_set(&env, "x", syn_int(10));
        let mut spec = SpeculativeEngine::new();
        let mut ctx = spec.begin(&env, "test");
        env_set(&env, "x", syn_int(42));
        spec.commit(&mut ctx);
        assert_eq!(env_get_int(&env, "x"), Some(42));
    }

    #[test]
    fn fork() {
        let env = Environment::root("global");
        env_set(&env, "x", syn_int(10));
        let mut spec = SpeculativeEngine::new();
        let branches: Vec<BranchFn> = vec![
            Box::new(|benv: &Rc<RefCell<Environment>>| {
                benv.borrow_mut().bindings.insert("x".to_string(), syn_int(100));
                syn_text("a")
            }),
            Box::new(|benv: &Rc<RefCell<Environment>>| {
                benv.borrow_mut().bindings.insert("x".to_string(), syn_int(200));
                syn_text("b")
            }),
        ];
        let results = spec.fork(&env, branches);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0.to_string(), "a");
        assert_eq!(results[1].0.to_string(), "b");
        spec.choose_and_apply(&env, &results, 1);
        assert_eq!(env_get_int(&env, "x"), Some(200));
    }
}

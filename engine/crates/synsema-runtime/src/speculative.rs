//! Ejecución especulativa — runtime reversible. Port de
//! `synsema/runtime/speculative.py`.
//!
//! Permite forkear el estado, probar enfoques, hacer rollback si algo falla, y
//! comparar resultados antes de commitear (como una transacción o branch de git):
//! snapshot del entorno → ejecutar especulativamente → rollback (restaura) /
//! commit (descarta) / fork (N branches independientes) + choose_and_apply.

use synsema_core::types::SynMap;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;


use synsema_core::interpreter::Environment;
use synsema_core::types::SynValue;

/// Copia profunda de un valor (list/map → nuevos Rc; el resto clona). Espeja el
/// `deepcopy` de Python (con fallback a clonar tasks/builtins).
fn deep_copy(v: &SynValue) -> SynValue {
    copy_at(v, 0)
}

fn copy_child<R>(v: &SynValue, index: usize, f: impl FnOnce(&SynValue) -> R) -> Option<R> {
    match v {
        SynValue::List(l) => l.borrow().as_values()?.get(index).map(f),
        SynValue::Map(m) => m.borrow().get_index(index).map(|(_, v)| f(v)),
        _ => None,
    }
}

fn copy_leaf(v: &SynValue) -> Option<SynValue> {
    match v {
        SynValue::List(l) => {
            let b = l.borrow();
            b.as_values().is_none().then(|| synsema_core::types::syn_list_of(b.clone()))
        }
        SynValue::Map(_) => None,
        _ => Some(v.clone()),
    }
}

fn rebuild(v: &SynValue, values: Vec<SynValue>) -> SynValue {
    match v {
        SynValue::List(_) => synsema_core::types::syn_list(values),
        SynValue::Map(m) => {
            let m = m.borrow();
            let mut out = SynMap::with_capacity(m.len());
            for (index, value) in values.into_iter().enumerate() {
                out.insert(m.get_index(index).unwrap().0.clone(), value);
            }
            synsema_core::types::syn_map(out)
        }
        _ => unreachable!(),
    }
}

fn copy_at(v: &SynValue, depth: usize) -> SynValue {
    if let Some(v) = copy_leaf(v) { return v; }
    if depth == 32 { return copy_tail(v); }
    let mut out = Vec::new();
    while let Some(v) = copy_child(v, out.len(), |v| copy_at(v, depth + 1)) { out.push(v); }
    rebuild(v, out)
}

#[cold]
#[inline(never)]
fn copy_tail(v: &SynValue) -> SynValue {
    let mut stack = vec![(v.clone(), Vec::new())];
    loop {
        let (v, out) = stack.last_mut().unwrap();
        match copy_child(v, out.len(), |v| copy_leaf(v).ok_or_else(|| v.clone())) {
            Some(Ok(v)) => out.push(v),
            Some(Err(v)) => stack.push((v, Vec::new())),
            None => {
                let (v, out) = stack.pop().unwrap();
                let v = rebuild(&v, out);
                if let Some((_, out)) = stack.last_mut() { out.push(v); }
                else { return v; }
            }
        }
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
        let bindings = e.bindings.iter().map(|(k, v)| (k.to_string(), deep_copy(v))).collect();
        let parent_snapshot = e.parent.as_ref().map(|p| Box::new(EnvironmentSnapshot::new(p)));
        EnvironmentSnapshot { name: e.name.to_string(), bindings, parent_snapshot }
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
    use synsema_core::types::{syn_int, syn_text};

    fn env_get_int(env: &Rc<RefCell<Environment>>, key: &str) -> Option<i64> {
        match env.borrow().bindings.get(key) {
            Some(SynValue::Number(synsema_core::number::Number::Int(i))) => Some(*i),
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
                benv.borrow_mut().bindings.insert("x", syn_int(100));
                syn_text("a")
            }),
            Box::new(|benv: &Rc<RefCell<Environment>>| {
                benv.borrow_mut().bindings.insert("x", syn_int(200));
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

#[cfg(test)]
mod deep_tests {
    use super::*;
    use synsema_core::{labels, types::{syn_int, syn_list, syn_map, Obj, ServerValue}};

    #[test]
    fn speculative_copy_is_deep_only_for_lists_and_maps() {
        for maps in [false, true] {
            let mut v = syn_int(7);
            for _ in 0..50000 {
                v = if maps { let mut m = SynMap::new(); m.insert("x", v); syn_map(m) }
                    else { syn_list(vec![v]) };
            }
            let copy = deep_copy(&v);
            assert!(copy.syn_equals(&v));
            let env = Environment::root("deep snapshot");
            env.borrow_mut().bindings.insert("x", v.clone());
            let snapshot = EnvironmentSnapshot::new(&env);
            env.borrow_mut().bindings.insert("x", syn_int(99));
            snapshot.restore(&env);
            let restored = synsema_core::interpreter::env_get(&env, "x").unwrap();
            assert!(restored.syn_equals(&v));
            match (&restored, &v) {
                (SynValue::List(a), SynValue::List(b)) => assert!(!synsema_core::types::ListRef::ptr_eq(a, b)),
                (SynValue::Map(a), SynValue::Map(b)) => assert!(!synsema_core::types::MapRef::ptr_eq(a, b)),
                _ => panic!(),
            }

            match (&v, &copy) {
                (SynValue::List(a), SynValue::List(b)) => assert!(!synsema_core::types::ListRef::ptr_eq(a, b)),
                (SynValue::Map(a), SynValue::Map(b)) => assert!(!synsema_core::types::MapRef::ptr_eq(a, b)),
                _ => panic!(),
            }
            let (mut left, mut right) = (v.clone(), copy.clone());
            for _ in 0..100 {
                match (&left, &right) {
                    (SynValue::List(a), SynValue::List(b)) => {
                        assert!(!synsema_core::types::ListRef::ptr_eq(a, b));
                        let pair = (a.borrow().get(0).unwrap(), b.borrow().get(0).unwrap());
                        (left, right) = pair;
                    }
                    (SynValue::Map(a), SynValue::Map(b)) => {
                        assert!(!synsema_core::types::MapRef::ptr_eq(a, b));
                        let pair = (a.borrow().get("x").unwrap().clone(), b.borrow().get("x").unwrap().clone());
                        (left, right) = pair;
                    }
                    _ => panic!(),
                }
            }
            for opaque in [labels::mark(v.clone(), labels::label_from(&["p"])),
                           SynValue::Server(Obj::new(ServerValue::Content(Box::new(v))))] {
                let copy = deep_copy(&opaque);
                match (&opaque, &copy) {
                    (SynValue::Private(a), SynValue::Private(b)) => assert!(Obj::ptr_eq(a, b)),
                    (SynValue::Server(a), SynValue::Server(b)) => assert!(Obj::ptr_eq(a, b)),
                    _ => panic!(),
                }
            }
        }
    }
}

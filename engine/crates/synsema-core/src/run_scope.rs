//! v0.6.51 (G1, `specs/v0.6.51-modelos.md`): el estado de UNA corrida que antes era del proceso.
//!
//! Un proceso de `synsema` corre un programa, pero un embebedor o un binario de tests corre varios, a
//! veces a la vez (los tests del runtime levantan más de cien `serve` en el mismo proceso). Lo que es
//! de la corrida —¿es un `serve`?, ¿ya abrió su puerto?, su `shutdown`, la identidad mTLS que declaró,
//! el texto con el que se redacta un valor privado— colgaba de un `static`: el primero ganaba, y un
//! `shutdown()` dejaba al proceso entero drenando.
//!
//! Como el `http.Server` de Go (cada servidor tiene su `Shutdown`) y su `context.Context` (el estado
//! viaja con el trabajo, no con el proceso): un `Arc<RunScope>` lo crea quien empieza la corrida y lo
//! comparten todos sus intérpretes (workers de `serve`, cron, agentes, `parallel_map`). Un builtin lo
//! lee de su intérprete (`Interpreter::run_scope`); lo que corre más abajo y no ve al intérprete (el
//! TLS del cliente, el `Display` de un valor privado) lo lee de la corrida en curso del hilo
//! ([`current`]), que fijan `Interpreter::execute` y cada unidad de trabajo al empezar
//! ([`RunScope::enter`]). Lo que sí es del proceso (las señales, los hilos del pool) sigue siéndolo.

use std::any::Any;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Default)]
pub struct RunScope {
    /// La corrida es un `serve` (top-level, workers, cron, agentes).
    serve: AtomicBool,
    /// El bloque `serve` ya abrió su puerto: desde ahí `exit()` cortaría requests en vuelo.
    bound: AtomicBool,
    /// El conjunto de principales que declara el programa (el texto de `private(…)`).
    redaction: RwLock<String>,
    /// Lo que otras capas (stdlib, runtime) cuelgan de la corrida, uno por tipo.
    ext: Mutex<Vec<Arc<dyn Any + Send + Sync>>>,
}

impl RunScope {
    pub fn new() -> Arc<RunScope> {
        Arc::new(RunScope::default())
    }

    pub fn mark_serve(&self) {
        self.serve.store(true, Ordering::SeqCst);
    }

    pub fn is_serve(&self) -> bool {
        self.serve.load(Ordering::SeqCst)
    }

    pub fn mark_bound(&self) {
        self.bound.store(true, Ordering::SeqCst);
    }

    pub fn is_bound(&self) -> bool {
        self.bound.load(Ordering::SeqCst)
    }

    pub fn set_redaction(&self, text: &str) {
        if let Ok(mut g) = self.redaction.write() {
            if *g != text {
                g.clear();
                g.push_str(text);
            }
        }
    }

    pub fn redaction(&self) -> String {
        self.redaction.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// El estado de tipo `T` de esta corrida (se crea con `Default` la primera vez).
    pub fn ext<T: Any + Send + Sync + Default>(&self) -> Arc<T> {
        let mut g = self.ext.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(found) = g.iter().find_map(|e| e.clone().downcast::<T>().ok()) {
            return found;
        }
        let made = Arc::new(T::default());
        g.push(made.clone());
        made
    }

    /// Este hilo trabaja para esta corrida hasta que se suelte el guard (que restaura la anterior:
    /// un hilo del pool de `serve` atiende corridas distintas, una por vez).
    pub fn enter(self: &Arc<Self>) -> RunEnter {
        let prev = CURRENT.with(|c| c.replace(Some(self.clone())));
        RunEnter(prev)
    }
}

impl RunScope {
    /// Este hilo trabaja para esta corrida mientras viva (los hilos de un runtime tokio de un
    /// `serve`, que son de esa corrida y de ninguna otra).
    pub fn adopt(self: &Arc<Self>) {
        CURRENT.with(|c| *c.borrow_mut() = Some(self.clone()));
    }
}

/// Un trabajo que va a correr en otro hilo para la corrida en curso de éste (la que haya: un hilo
/// sin corrida da un trabajo sin corrida). Como el `context.Context` de Go, que viaja con el trabajo.
pub fn carry<R>(f: impl FnOnce() -> R) -> impl FnOnce() -> R {
    let run = current();
    move || {
        let _run = run.as_ref().map(|r| r.enter());
        f()
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<RunScope>>> = const { RefCell::new(None) };
}

/// La corrida para la que trabaja este hilo, si alguna entró.
pub fn current() -> Option<Arc<RunScope>> {
    CURRENT.with(|c| c.borrow().clone())
}

#[must_use]
pub struct RunEnter(Option<Arc<RunScope>>);

impl Drop for RunEnter {
    fn drop(&mut self) {
        let prev = self.0.take();
        CURRENT.with(|c| *c.borrow_mut() = prev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Counter(std::sync::atomic::AtomicUsize);

    #[test]
    fn two_runs_keep_their_own_state_and_the_thread_restores_the_previous_one() {
        let a = RunScope::new();
        let b = RunScope::new();
        a.mark_serve();
        a.mark_bound();
        a.set_redaction("app");
        assert!(!b.is_serve() && !b.is_bound() && b.redaction().is_empty());
        a.ext::<Counter>().0.fetch_add(1, Ordering::SeqCst);
        assert_eq!(a.ext::<Counter>().0.load(Ordering::SeqCst), 1);
        assert_eq!(b.ext::<Counter>().0.load(Ordering::SeqCst), 0);
        assert!(current().is_none());
        {
            let _ea = a.enter();
            assert!(current().is_some_and(|c| Arc::ptr_eq(&c, &a)));
            {
                let _eb = b.enter();
                assert!(current().is_some_and(|c| Arc::ptr_eq(&c, &b)));
            }
            assert!(current().is_some_and(|c| Arc::ptr_eq(&c, &a)));
        }
        assert!(current().is_none());
    }

    #[test]
    fn carry_takes_the_run_of_the_thread_that_made_the_job() {
        let a = RunScope::new();
        let job = {
            let _ea = a.enter();
            carry(current)
        };
        let seen = std::thread::spawn(move || (job(), current())).join().unwrap();
        assert!(seen.0.is_some_and(|c| Arc::ptr_eq(&c, &a)), "el trabajo corre para la corrida de quien lo armó");
        assert!(seen.1.is_none(), "y el hilo la suelta al terminar");
        assert!(carry(current)().is_none(), "un hilo sin corrida da un trabajo sin corrida");
    }

    /// v0.6.51 (ronda 1, M2): `synsema test` es una entrada del host como `execute`: el setup y
    /// cada bloque `test` corren dentro de la corrida del intérprete.
    #[test]
    fn g1_test_blocks_run_inside_the_interpreters_run() {
        use crate::interpreter::Interpreter;
        use crate::types::SynValue;
        let mut i = Interpreter::new();
        let mine = i.run_scope().clone();
        i.register_builtin(
            "same_run",
            0,
            std::rc::Rc::new(move |_, _, _| {
                Ok(SynValue::Bool(current().is_some_and(|c| Arc::ptr_eq(&c, &mine))))
            }),
        );
        let p = crate::parser::parse_source(
            "let s be same_run()\ntest \"t\"\n    assert_eq(s, true)\n    assert_eq(same_run(), true)\n",
            "g1t.syn",
        )
        .unwrap();
        let out = i.run_test_blocks(&p);
        assert!(!out.is_empty());
        assert!(out.iter().all(|o| o.passed), "{:?}", out.iter().map(|o| &o.message).collect::<Vec<_>>());
    }
}

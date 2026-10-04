//! v0.6.42 — "este hilo está esperando": la señal con la que el pool de `serve` no deja que una
//! ruta que espera (un `sleep`, un `wait_for`, una llamada HTTP o al LLM, un `select`) retenga
//! capacidad de CPU. Es el `handoff` del planificador de Go ante una syscall bloqueante: el que
//! espera suelta su permiso de ejecución y el pool puede poner otro hilo a trabajar.
//!
//! Cada builtin que bloquea abre una sección con `waiting()` y la cierra al soltar el guard.
//! El pool instala su gancho POR HILO (`set_thread_hook`) en sus workers; en cualquier otro hilo
//! (`run`, tests, agentes, wasm) no hay gancho y el costo es leer un thread-local. Las secciones
//! se pueden anidar (un reintento con `sleep` dentro de una llamada que ya espera): el gancho sólo
//! ve la entrada a la primera y la salida de la última.

use std::cell::Cell;

/// Gancho del pool: `true` al empezar a esperar, `false` al terminar (puede bloquear un instante
/// hasta recuperar un permiso de ejecución). Un puntero a función: sin asignación ni `Rc`.
pub type WaitHook = fn(bool);

thread_local! {
    static HOOK: Cell<Option<WaitHook>> = const { Cell::new(None) };
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Instala (o quita, con `None`) el gancho de ESTE hilo. Lo llama el pool al crear un worker.
pub fn set_thread_hook(hook: Option<WaitHook>) {
    HOOK.with(|h| h.set(hook));
}

/// Guard de una sección de espera; ver `waiting`.
#[must_use = "la espera dura lo que vive el guard: `let _w = waiting();`"]
pub struct Waiting {
    hook: Option<WaitHook>,
}

/// Abre una sección de espera en este hilo. `let _w = waiting();` antes de bloquear.
#[inline]
pub fn waiting() -> Waiting {
    let hook = HOOK.with(|h| h.get());
    if let Some(f) = hook {
        let outer = DEPTH.with(|d| {
            let n = d.get();
            d.set(n + 1);
            n == 0
        });
        if outer {
            f(true);
        }
    }
    Waiting { hook }
}

impl Drop for Waiting {
    #[inline]
    fn drop(&mut self) {
        if let Some(f) = self.hook {
            let last = DEPTH.with(|d| {
                let n = d.get().saturating_sub(1);
                d.set(n);
                n == 0
            });
            if last {
                f(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static EVENTS: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn record(on: bool) {
        EVENTS.with(|e| e.borrow_mut().push(on));
    }

    #[test]
    fn without_a_hook_it_does_nothing() {
        let _w = waiting();
        EVENTS.with(|e| assert!(e.borrow().is_empty()));
    }

    #[test]
    fn nested_sections_signal_once() {
        set_thread_hook(Some(record));
        {
            let _a = waiting();
            {
                let _b = waiting();
            }
            EVENTS.with(|e| assert_eq!(*e.borrow(), vec![true]));
        }
        EVENTS.with(|e| assert_eq!(*e.borrow(), vec![true, false]));
        set_thread_hook(None);
    }
}

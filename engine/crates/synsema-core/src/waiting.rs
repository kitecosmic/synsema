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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Gancho del pool: `true` al empezar a esperar, `false` al terminar (puede bloquear un instante
/// hasta recuperar un permiso de ejecución). Un puntero a función: sin asignación ni `Rc`.
pub type WaitHook = fn(bool);

thread_local! {
    static HOOK: Cell<Option<WaitHook>> = const { Cell::new(None) };
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    static CANCEL: std::cell::RefCell<Option<Arc<AtomicBool>>> = const { std::cell::RefCell::new(None) };
}

/// La cancelación de lo que corre en ESTE hilo (la request de `serve`, el agente), para las
/// esperas que no tienen el intérprete a mano (el lugar de presupuesto LLM). La fija el
/// intérprete al adoptar un token (`set_cancel_token`).
pub fn set_thread_cancel(flag: Option<Arc<AtomicBool>>) {
    CANCEL.with(|c| *c.borrow_mut() = flag);
}

/// ¿Se canceló lo que corre en este hilo? `false` si nadie fijó un token (`run`, tests).
pub fn thread_cancelled() -> bool {
    CANCEL.with(|c| c.borrow().as_ref().is_some_and(|f| f.load(Ordering::Relaxed)))
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

/// Guard de una sección que vuelve a USAR CPU dentro de una espera (el callback de un stream
/// HTTP que corre código del usuario, una task de `on_reconnect`): retoma el permiso mientras
/// corre y lo vuelve a soltar al terminar. Fuera de una espera no hace nada.
#[must_use = "la sección dura lo que vive el guard: `let _r = resumed();`"]
pub struct Resumed {
    hook: Option<WaitHook>,
    /// La profundidad de espera de afuera: adentro del callback vale 0 (una espera ahí suelta el
    /// permiso de nuevo) y se restaura al salir.
    depth: u32,
}

/// Abre una sección que usa CPU dentro de una espera (ver `Resumed`).
#[inline]
pub fn resumed() -> Resumed {
    let hook = HOOK.with(|h| h.get());
    let depth = DEPTH.with(|d| d.get());
    match hook {
        Some(f) if depth > 0 => {
            f(false);
            DEPTH.with(|d| d.set(0));
            Resumed { hook: Some(f), depth }
        }
        _ => Resumed { hook: None, depth: 0 },
    }
}

impl Drop for Resumed {
    #[inline]
    fn drop(&mut self) {
        if let Some(f) = self.hook {
            DEPTH.with(|d| d.set(self.depth));
            f(true);
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

    /// Auditoría ronda 2 (R5): una espera DENTRO de un callback (que corre con permiso) vuelve a
    /// soltar el permiso; al salir del callback se sigue esperando como antes.
    #[test]
    fn a_wait_inside_a_resumed_callback_releases_again() {
        EVENTS.with(|e| e.borrow_mut().clear());
        set_thread_hook(Some(record));
        {
            let _w = waiting(); // true
            {
                let _r = resumed(); // false (corre el callback)
                {
                    let _w2 = waiting(); // true (espera adentro del callback)
                } // false
            } // true (vuelve a la espera de afuera)
        } // false
        EVENTS.with(|e| assert_eq!(*e.borrow(), vec![true, false, true, false, true, false]));
        set_thread_hook(None);
    }
}

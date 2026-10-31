//! v0.6.52 (ronda 4, A1) — lo que un builtin sostiene mientras corre.
//!
//! Un builtin juzga una ruta (`require`) y después actúa sobre ella por nombre. Para que una
//! carpeta no cambie de dueño en el medio (un hijo aislado que arranca con escritura en ella), el
//! chequeo deja acá una «tenencia» y el intérprete la suelta cuando el builtin vuelve: quien presta
//! la carpeta espera a que se suelten las de los otros hilos (`isolated_areas::borrow`).
//!
//! Por hilo, como `audit_loc`, y con su mismo atómico: sin `exec` el intérprete no hace nada más por
//! llamada que antes. Se habilita al conceder `exec` (sin `exec` no hay hijos que presten nada).

use std::any::Any;
use std::cell::{Cell, RefCell};

thread_local! {
    /// Cuántos builtins hay en curso en este hilo (anidan: un callback que llama a otro).
    static FRAMES: Cell<usize> = const { Cell::new(0) };
    /// Desde dónde de `HELD` es del builtin de más adentro (`release`).
    static TOP: Cell<usize> = const { Cell::new(0) };
    /// El builtin de más adentro (`frame`; 0 fuera de uno) y el último número dado.
    static CURRENT: Cell<u64> = const { Cell::new(0) };
    static LAST: Cell<u64> = const { Cell::new(0) };
    static HELD: RefCell<Vec<Box<dyn Any>>> = const { RefCell::new(Vec::new()) };
}

/// El interruptor comparte el atómico de `audit_loc` (ver `audit_loc::around`).
pub fn enable() {
    crate::audit_loc::enable_bit(crate::audit_loc::HOLD);
}

pub fn enabled() -> bool {
    crate::audit_loc::around() & crate::audit_loc::HOLD != 0
}

/// Un builtin en curso: al soltarse (también con un pánico) suelta lo que se sostuvo adentro.
pub struct Frame {
    mark: usize,
    outer: usize,
    outer_id: u64,
}

/// Entra a un builtin.
pub fn enter() -> Frame {
    FRAMES.with(|f| f.set(f.get() + 1));
    let mark = HELD.with(|h| h.borrow().len());
    let id = LAST.with(|l| {
        l.set(l.get() + 1);
        l.get()
    });
    Frame { mark, outer: TOP.with(|t| t.replace(mark)), outer_id: CURRENT.with(|c| c.replace(id)) }
}

/// Ronda 6 (M1): qué builtin está en curso en este hilo (único en el hilo; 0 fuera de uno). Quien
/// sostiene muchas cosas en el mismo builtin las junta en una sola tenencia.
pub fn frame() -> u64 {
    CURRENT.with(|c| c.get())
}

impl Drop for Frame {
    fn drop(&mut self) {
        FRAMES.with(|f| f.set(f.get().saturating_sub(1)));
        TOP.with(|t| t.set(self.outer));
        CURRENT.with(|c| c.set(self.outer_id));
        // Se sacan primero y se sueltan después: soltar puede volver a mirar este hilo.
        let extra = HELD.with(|h| {
            let mut h = h.borrow_mut();
            let at = self.mark.min(h.len());
            h.split_off(at)
        });
        drop(extra);
    }
}

/// Sostiene `g` hasta que vuelva el builtin en curso. Fuera de un builtin no lo sostiene (lo suelta
/// enseguida) y devuelve `false`.
pub fn hold(g: Box<dyn Any>) -> bool {
    if FRAMES.with(|f| f.get()) == 0 {
        drop(g);
        return false;
    }
    HELD.with(|h| h.borrow_mut().push(g));
    true
}

/// Ronda 5 (M2): suelta ya lo que sostiene el builtin en curso (no lo de los de afuera). Para un
/// builtin que no vuelve a actuar por nombre sobre lo que juzgó y todavía tarda en volver: `run`,
/// una vez lanzado el hijo, sólo espera.
pub fn release() {
    let at = TOP.with(|t| t.get());
    let extra = HELD.with(|h| {
        let mut h = h.borrow_mut();
        let at = at.min(h.len());
        h.split_off(at)
    });
    drop(extra);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    /// Anota cuándo se soltó.
    struct Flag(Rc<Cell<bool>>);

    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// Ronda 5 (M2): `release` suelta lo del builtin de más adentro; lo de un builtin de afuera (el
    /// que llamó al callback) sigue sostenido hasta que ése vuelve.
    #[test]
    fn release_lets_go_only_of_the_innermost_builtin() {
        let (outer, inner) = (Rc::new(Cell::new(false)), Rc::new(Cell::new(false)));
        let f1 = enter();
        assert!(hold(Box::new(Flag(outer.clone()))));
        {
            let _f2 = enter();
            assert!(hold(Box::new(Flag(inner.clone()))));
            release();
            assert!(inner.get() && !outer.get());
        }
        assert!(!outer.get());
        drop(f1);
        assert!(outer.get());
    }

    /// Ronda 6 (M1): cada builtin tiene su número; al volver uno de adentro, `frame` vuelve a ser el
    /// del de afuera, y fuera de todos es 0.
    #[test]
    fn each_builtin_has_its_own_frame() {
        assert_eq!(frame(), 0);
        let f1 = enter();
        let a = frame();
        assert_ne!(a, 0);
        {
            let _f2 = enter();
            assert!(frame() != a && frame() != 0);
        }
        assert_eq!(frame(), a, "volvió el de adentro");
        drop(f1);
        assert_eq!(frame(), 0);
        let _f3 = enter();
        assert!(frame() != a, "un builtin nuevo no repite el número");
    }
}

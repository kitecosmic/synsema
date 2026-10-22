//! `BuiltinTask::meta` (specs/compute-rendimiento.md F1.3) es la lectura de las tablas para cada
//! builtin, hecha una vez al registrarlo en vez de en cada llamada. Tiene que decir exactamente lo
//! que dicen las tablas.

use std::rc::Rc;
use synsema_core::builtin_arity::{arity_of, kwargs_of, BUILTIN_ARITY, BUILTIN_KWARGS};
use synsema_core::interpreter::{BuiltinTask, Interpreter, LINEAGE_SOURCES};
use synsema_core::types::SynValue;

fn expected(b: &BuiltinTask) -> ((usize, Option<usize>), &'static [&'static str], bool, bool) {
    let arity = arity_of(&b.name).unwrap_or(if b.param_count >= 0 {
        (b.param_count as usize, Some(b.param_count as usize))
    } else {
        (0, None)
    });
    (
        arity,
        kwargs_of(&b.name),
        LINEAGE_SOURCES.contains(&b.name.as_str()),
        b.name.starts_with(|c: char| c.is_ascii_uppercase()),
    )
}

fn check(b: &BuiltinTask) {
    let (arity, kwargs, lineage, constructor) = expected(b);
    assert_eq!(b.meta.arity, arity, "aridad de {}", b.name);
    assert_eq!(b.meta.kwargs, kwargs, "kwargs de {}", b.name);
    assert_eq!(b.meta.lineage_source, lineage, "linaje de {}", b.name);
    assert_eq!(b.meta.constructor, constructor, "constructor {}", b.name);
}

#[test]
fn every_registered_builtin_reads_the_tables() {
    let interp = Interpreter::new();
    let env = interp.global_env.borrow();
    let mut n = 0;
    for v in env.bindings.values() {
        if let SynValue::Builtin(b) = v {
            check(b);
            n += 1;
        }
    }
    assert!(n > 100, "sólo {} builtins registrados en el core", n);
}

/// Los de las tablas que registra el stdlib (no están en un `Interpreter` del core solo), más
/// uno con `param_count` fijo y otro variádico que no figuran en ninguna tabla.
#[test]
fn every_table_entry_is_read_the_same() {
    let noop: synsema_core::interpreter::BuiltinFn = Rc::new(|_, _, _| Ok(SynValue::Nothing));
    let mut names: Vec<&str> = BUILTIN_ARITY.iter().map(|(n, _, _)| *n).collect();
    names.extend(BUILTIN_KWARGS.iter().map(|(n, _)| *n));
    names.extend(LINEAGE_SOURCES.iter().copied());
    for name in names {
        for pc in [-1, 0, 2] {
            check(&BuiltinTask::new(name, pc, None, noop.clone()));
        }
    }
    for (name, pc) in [("no_esta_en_ninguna_tabla", 3), ("tampoco", -1), ("Point", 2), ("Order.paid", 1)] {
        check(&BuiltinTask::new(name, pc, None, noop.clone()));
    }
}

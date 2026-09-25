//! Tamaño de los tipos que el intérprete mueve en cada nodo (specs/compute-rendimiento.md §3.9):
//! toda evaluación devuelve un `Result<SynValue, Control>`, así que su tamaño se paga en cada
//! nodo aunque el error no ocurra nunca. Si un número de acá sube, es una regresión; si baja
//! (F1.10), se actualiza con el cambio que lo bajó.

use std::mem::size_of;
use synsema_core::ast::{Node, NodeKind};
use synsema_core::interpreter::{Control, RuntimeError};
use synsema_core::number::Number;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::SynValue;

#[test]
fn hot_types_do_not_grow() {
    let rows: &[(&str, usize, usize)] = &[
        // (tipo, tamaño, tope: el de v0.6.30, 64 bits)
        ("Number", size_of::<Number>(), 32),
        ("SynValue", size_of::<SynValue>(), 32),
        ("RuntimeError", size_of::<RuntimeError>(), 128),
        ("Control", size_of::<Control>(), 128),
        ("Result<SynValue, Control>", size_of::<Result<SynValue, Control>>(), 128),
        ("SourceLocation", size_of::<SourceLocation>(), 48),
        ("NodeKind", size_of::<NodeKind>(), 216),
        ("Node", size_of::<Node>(), 264),
    ];
    let mut report = String::new();
    let mut grew = 0;
    for (name, size, cap) in rows {
        let mark = if size > cap {
            grew += 1;
            "!!"
        } else {
            "ok"
        };
        report.push_str(&format!("  {}  {:<28} {} bytes (tope {})\n", mark, name, size, cap));
    }
    eprintln!("tamaños:\n{}", report);
    assert_eq!(grew, 0, "creció un tipo del camino caliente:\n{}", report);
}

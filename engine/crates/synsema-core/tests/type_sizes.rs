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
        // (tipo, tamaño, tope en 64 bits). v0.6.30: Number/SynValue 32, RuntimeError/Control/Result 128,
        // SourceLocation 48, Node 264; F1.10 los bajó (error y BigInt en Box, archivo en Arc<str>).
        ("Number", size_of::<Number>(), 24),
        ("SynValue", size_of::<SynValue>(), 24),
        ("RuntimeError", size_of::<RuntimeError>(), 8),
        ("Control", size_of::<Control>(), 32),
        ("Result<SynValue, Control>", size_of::<Result<SynValue, Control>>(), 32),
        ("SourceLocation", size_of::<SourceLocation>(), 40),
        ("NodeKind", size_of::<NodeKind>(), 216),
        ("Node", size_of::<Node>(), 256),
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

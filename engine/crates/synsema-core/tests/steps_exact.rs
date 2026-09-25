//! `steps()` cuenta un paso por nodo evaluado, sin importar por qué camino interno se ejecutó la
//! sentencia (specs/compute-rendimiento.md §3.6). En v0.6.29/v0.6.30 el camino "en el lugar" de
//! `set` lo rompía: `set x to x + 1` contaba 5 pasos y `set xs to append(xs, 2)` 4, cuando la
//! referencia (sin atajos) cuenta 4 y 5 — el destino de un `set` no se evalúa como expresión.
//!
//! Un solo `#[test]`: prende y apaga el modo referencia, que es del proceso.

use synsema_core::interpreter::{run_source, set_reference_mode};

/// Pasos que cuenta `stmt` (después de `prelude`): la diferencia entre dos `steps()`, menos los 3
/// nodos de `let b be steps()` (let, llamada, identificador).
fn steps_of(prelude: &str, stmt: &str, reference: bool) -> i64 {
    let src = format!("{}\nlet a be steps()\n{}\nlet b be steps()\nprint(b - a - 3)\n", prelude, stmt);
    set_reference_mode(reference);
    let r = run_source(&src, "<steps>");
    set_reference_mode(false);
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output.last().expect("sin salida").parse().expect("no es un número")
}

#[test]
fn shortcuts_count_the_same_steps_as_the_reference() {
    // (preludio, sentencia, pasos de la referencia si se fija el número)
    let cases: &[(&str, &str, Option<i64>)] = &[
        // La tabla de §3.6.
        ("let x be 0", "set x to 1 + x", Some(4)),
        ("let x be 0", "set x to x + 1", Some(4)),
        ("let xs be [1]", "set xs to append([], 2)", Some(5)),
        ("let xs be [1]", "set xs to append(xs, 2)", Some(5)),
        // Cada forma del atajo, contra la referencia.
        ("let xs be [1]", "set xs to xs + [2]", None),
        ("let xs be [1]", "set xs to insert(xs, 0, 9)", None),
        ("let m be {\"a\": 1}", "set m to merge(m, {\"b\": 2})", None),
        ("let m be {\"a\": 1}", "set m to merge(m, {\"b\": 2}, {\"c\": 3})", None),
        ("let m be {\"a\": [1]}", "set m.a to append(m.a, 2)", None),
        ("let m be {\"a\": [1]}", "set m[\"a\"] to append(m[\"a\"], 2)", None),
        ("let m be {\"a\": [1]}\nlet k be \"a\"", "set m[k] to append(m[k], 2)", None),
        ("let m be {\"a\": {\"b\": [1]}}", "set m.a.b to append(m.a.b, 2)", None),
        ("let ys be [[1], [2]]", "set ys[1] to append(ys[1], 3)", None),
        ("let ys be [[1], [2]]\nlet j be 0", "set ys[j] to ys[j] + [3, 4]", None),
        // Formas que parecen el atajo y no lo son (el valor no es contenedor, o no es P).
        ("let s be \"a\"", "set s to s + \"b\"", None),
        ("let f be 1.5", "set f to f + 1", None),
        ("let xs be [1]\nlet ys be [2]", "set xs to append(ys, 3)", None),
        ("let m be {\"a\": 1}", "set m.a to m.a + 1", None),
    ];
    let mut bad = Vec::new();
    for (prelude, stmt, fixed) in cases {
        let reference = steps_of(prelude, stmt, true);
        let fast = steps_of(prelude, stmt, false);
        if fast != reference {
            bad.push(format!("  {:<42} atajos {} / referencia {}", stmt, fast, reference));
        }
        if let Some(n) = fixed {
            if reference != *n {
                bad.push(format!("  {:<42} la referencia cuenta {}, §3.6 dice {}", stmt, reference, n));
            }
        }
    }
    assert!(bad.is_empty(), "steps() depende del camino interno:\n{}", bad.join("\n"));
}

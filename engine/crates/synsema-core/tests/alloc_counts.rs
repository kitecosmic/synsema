//! Asignaciones de heap por construcción (specs/compute-rendimiento.md §2.3 y §7): cuántas veces
//! pide memoria el intérprete en cada vuelta de un bucle que repite UNA construcción. Es la
//! métrica exacta del plan de rendimiento (el tiempo tiene ruido; esto no) y corre en cualquier
//! sistema, CI incluido.
//!
//! Cómo se mide: un allocator global que cuenta, el mismo programa con N = 1000 y N = 2000
//! vueltas, y la diferencia / 1000 (el arranque, el parser y la primera vuelta se cancelan). Los
//! valores coinciden con los del shim `LD_PRELOAD` de `specs/compute-bench/alloc/count.c` sobre el
//! binario de Linux. Un cambio en esta tabla es un cambio de rendimiento: si baja, se actualiza el
//! número con el cambio que lo bajó; si sube, es una regresión.
//!
//! Un solo `#[test]` a propósito: el contador es del proceso, y otro test corriendo en paralelo
//! en este mismo binario lo ensuciaría.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: delega todo en `System` sin tocar punteros ni tamaños; sólo cuenta.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Un bucle `while` de N vueltas con `body` adentro (más el `set i to i + 1` del contador).
fn while_loop(prelude: &str, body: &str, n: u64) -> String {
    format!("{}let x be 0\nlet i be 0\nwhile i < {}\n{}    set i to i + 1\n", prelude, n, body)
}

fn allocs_for(source: &str) -> u64 {
    let before = ALLOCS.load(Ordering::SeqCst);
    let r = synsema_core::interpreter::run_source(source, "<alloc>");
    let after = ALLOCS.load(Ordering::SeqCst);
    assert!(r.success, "el programa falló: {:?}\n{}", r.errors, source);
    after - before
}

/// Mallocs por vuelta: (N=2000 − N=1000) / 1000, exacto. Antes, una corrida corta de
/// calentamiento: lo que se inicializa una vez por proceso (la tabla de aridades de los builtins
/// es un `OnceLock`) no puede caer en una sola de las dos mediciones.
fn per_iteration(make: impl Fn(u64) -> String) -> Result<u64, String> {
    allocs_for(&make(10));
    let a = allocs_for(&make(1000));
    let b = allocs_for(&make(2000));
    let d = b.checked_sub(a).ok_or_else(|| format!("N=2000 pidió menos que N=1000 ({} < {})", b, a))?;
    if d % 1000 != 0 {
        return Err(format!("no es un número entero por vuelta: {} / 1000", d));
    }
    Ok(d / 1000)
}

/// Como `per_iteration`, para lo que arma una lista que crece al doble: entre N = 1000 y 2000 hay
/// a lo sumo un puñado de `realloc` que no son por fila (menos de 16 en total).
fn per_row_amortized(make: impl Fn(u64) -> String) -> Result<u64, String> {
    let a = allocs_for(&make(1000));
    let b = allocs_for(&make(2000));
    let d = b.checked_sub(a).ok_or_else(|| format!("N=2000 pidió menos que N=1000 ({} < {})", b, a))?;
    if d % 1000 >= 16 {
        return Err(format!("no es un número entero por fila: {} / 1000", d));
    }
    Ok(d / 1000)
}

#[test]
fn heap_allocations_per_construct() {
    // (nombre, preludio, cuerpo del bucle, mallocs por vuelta HOY con el bucle incluido).
    // El bucle base (`i < N` + `set i to i + 1`) no pide memoria: 0. Todo lo demás es lo que
    // agrega la construcción. (v0.6.30: 4 — la comparación de enteros pasaba por BigInt (F1.1),
    // `set i to i + 1` armaba un `Vec` para probar el camino en el lugar (F1.4) y cada `set`
    // creaba otra vez la clave del entorno (F1.5).)
    let while_cases: &[(&str, &str, &str, u64)] = &[
        ("bucle base", "", "", 0),
        ("expresión: variable", "", "    x\n", 0),
        ("set x to 5", "", "    set x to 5\n", 0),
        ("let y be 5", "", "    let y be 5\n", 0),
        ("set x to i + 1", "", "    set x to i + 1\n", 0),
        ("set x to f + 1.5", "let f be 0.5\n", "    set x to f + 1.5\n", 0),
        ("set x to i < 1", "", "    set x to i < 1\n", 0),
        ("set x to i == 1", "", "    set x to i == 1\n", 0),
        ("set x to i ** 1", "", "    set x to i ** 1\n", 3),
        ("set x to xs[1]", "let xs be [1, 2, 3]\n", "    set x to xs[1]\n", 0),
        ("set x to m.a", "let m be {\"a\": 1}\n", "    set x to m.a\n", 0),
        // F3.3: el literal sale del pool de constantes de la VM (suma una referencia); antes, 1.
        ("set x to \"hello\"", "", "    set x to \"hello\"\n", 0),
        ("when i < 0", "", "    when i < 0\n        set x to 1\n", 0),
        ("builtin abs(i)", "", "    set x to abs(i)\n", 0),
        ("llamada f()", "task f()\n    give 1\n", "    set x to f()\n", 0),
        ("llamada f(1)", "task f(p0)\n    give 1\n", "    set x to f(1)\n", 0),
        ("llamada f(1, 1)", "task f(p0, p1)\n    give 1\n", "    set x to f(1, 1)\n", 0),
        ("llamada f(1, 1, 1)", "task f(p0, p1, p2)\n    give 1\n", "    set x to f(1, 1, 1)\n", 0),
        ("llamada f(1, 1, 1, 1)", "task f(p0, p1, p2, p3)\n    give 1\n", "    set x to f(1, 1, 1, 1)\n", 0),
        ("llamada f(1, 1, 1, 1, 1)", "task f(p0, p1, p2, p3, p4)\n    give 1\n", "    set x to f(1, 1, 1, 1, 1)\n", 0),
        // F4.5: un malloc, el cuerpo con la forma compartida y los dos valores en línea. Antes: 3
        // (F4.4: la caja, las entradas y la tabla) y 5 (cada clave, un `String` propio).
        ("registro {\"id\": i, \"valor\": i}", "", "    set x to {\"id\": i, \"valor\": i}\n", 1),
        // F4.4: una clave de texto que ya está no asigna (antes: 1, un `String` que se tiraba).
        ("set m[k] (clave que ya está)", "let m be {\"a\": 1}\nlet k be \"a\"\n", "    set m[k] to i\n", 0),
        // F4.4: `set m.a` sobre una clave que ya está sólo cambia el valor (antes: 1).
        ("set m.a (clave que ya está)", "let m be {\"a\": 1}\n", "    set m.a to i\n", 0),
        // F4.6a: `set` con camino en la VM (sin armar el índice como texto en cada nivel).
        ("set xs[1] (camino)", "let xs be [1, 2, 3]
", "    set xs[1] to i
", 0),
        ("set bs[0].x (camino)", "let bs be [{\"x\": 1}]
", "    set bs[0].x to i
", 0),
        ("set m.a.b[j] (camino)", "let m be {\"a\": {\"b\": [1, 2]}}
let j be 1
", "    set m.a.b[j] to i
", 0),
        // F4.6b: un texto de hasta 15 B vive en línea (sin malloc); `+` agrega en el lugar si el
        // de la izquierda es de un solo dueño y, si no, copia una vez (antes: `format!` + la copia).
        ("texto corto \"ab\" + \"cd\"", "", "    set x to \"ab\" + \"cd\"
", 0),
        ("texto corto + número", "", "    set x to \"n=\" + i
", 0),
        ("texto largo + corto", "let t be \"un texto que no entra en línea\"
", "    set x to t + \"!\"
", 1),
        // La copia del largo justo y un `realloc` cuando el intermedio (único) crece.
        ("a + b + c (el intermedio en el lugar)", "let t be \"un texto que no entra en línea\"
", "    set x to t + \"!\" + \"?\"
", 2),
        // F4.6c: `text(x)` escribe en el texto (en línea hasta 15 B), sin un `String` (antes: 1).
        ("text(i)", "", "    set x to text(i)
", 0),
        // F4.4: `keys` comparte el texto de cada clave (antes: 4, uno por clave).
        ("keys(m) de 2 claves", "let m be {\"a\": 1, \"b\": 2}\n", "    set x to keys(m)\n", 2),
    ];

    let mut rows = Vec::new();
    for (name, prelude, body, expected) in while_cases {
        rows.push((*name, per_iteration(|n| while_loop(prelude, body, n)), *expected));
    }
    // F4.6c: `set s to s + …` sobre un texto de un solo dueño agrega en el lugar (crece al doble:
    // unos pocos `realloc` por corrida, no por vuelta). Antes: una copia de todo `s` por vuelta.
    rows.push(("set s to s + \"x\" (en el lugar)", per_row_amortized(|n| while_loop("let s be \"\"
", "    set s to s + \"x\"
", n)), 0));
    rows.push((
        "set s to s + text(i) + \",\"",
        per_row_amortized(|n| while_loop("let s be \"\"
", "    set s to s + text(i) + \",\"
", n)),
        0,
    ));
    // `each` sobre `range`: la vuelta (entorno nuevo + clave + tabla; el nombre formateado ya no, F1.6).
    rows.push(("vuelta de each + set x to 1", per_iteration(|n| format!("let x be 0\neach i in range(0, {})\n    set x to 1\n", n)), 0));
    // F4.8b: un builtin que llama una función por elemento, sin copiar la lista, sin `Vec` de
    // argumentos ni frame por llamada (antes: 2 por elemento, el `vec![item]` y los `CallArgs`, y
    // la copia de la lista entera).
    rows.push((
        "count_where con lambda, por elemento",
        per_row_amortized(|n| format!("let xs be range(0, {})\nlet c be count_where(xs, (x) => x % 3 == 0)\n", n)),
        0,
    ));
    rows.push((
        "reduce con lambda, por elemento",
        per_row_amortized(|n| format!("let xs be range(0, {})\nlet c be reduce(xs, (a, x) => a + x, 0)\n", n)),
        0,
    ));
    // F4.4: `csv_parse` por fila de 2 columnas: las cabeceras, claves una vez por llamada. Las
    // listas que crecen al doble suman unos pocos `realloc` por llamada (no por fila): se descuentan.
    rows.push((
        "csv_parse por fila",
        per_row_amortized(|n| {
            let body: String = (0..n).map(|i| format!("{},{}\\n", i, i)).collect();
            format!("let d be csv_parse(\"id,v\\n{}\", {{\"numbers\": true}})\n", body)
        }),
        1, // perf/tabular: sólo el malloc de la fila (el lector ya no arma un String por campo ni un Vec por fila; F4.5: 4, F4.4: 6, antes: 8)
    ));

    let mut report = String::new();
    let mut bad = 0;
    for (name, got, expected) in &rows {
        let line = match got {
            Ok(g) if g == expected => format!("  ok  {:<32} {}\n", name, g),
            Ok(g) => {
                bad += 1;
                format!("  !!  {:<32} {} (la tabla dice {})\n", name, g, expected)
            }
            Err(e) => {
                bad += 1;
                format!("  !!  {:<32} {}\n", name, e)
            }
        };
        report.push_str(&line);
    }
    eprintln!("mallocs por vuelta:\n{}", report);
    assert_eq!(bad, 0, "cambió la cantidad de asignaciones por construcción:\n{}", report);
}

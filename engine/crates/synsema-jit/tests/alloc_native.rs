//! F4.7b: leer datos en un bucle nativo no pide memoria (specs/compute-rendimiento.md, F4.7):
//! `xs[i]`, `m.k`, `m["k"]`, una lista anidada y `each` sobre una lista, 0 mallocs por vuelta. Los
//! valores con caja entran prestados (no se clonan, no se arman) y las lecturas de `abi` no piden
//! memoria. Mismo método que `synsema-core/tests/alloc_counts.rs` (N = 1000 y 2000 vueltas, la
//! diferencia / 1000), con el nivel nativo ansioso (el bucle entra a la segunda vuelta).
//!
//! Un solo `#[test]` a propósito: el contador es del proceso.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use synsema_core::native_tier;

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

fn allocs_for(source: &str) -> u64 {
    let before = ALLOCS.load(Ordering::SeqCst);
    let r = synsema_core::interpreter::run_source(source, "<alloc>");
    let after = ALLOCS.load(Ordering::SeqCst);
    assert!(r.success, "el programa falló: {:?}\n{}", r.errors, source);
    after - before
}

/// Mallocs por vuelta: (N=2000 − N=1000) / 1000.
fn per_iteration(make: impl Fn(u64) -> String) -> u64 {
    allocs_for(&make(10));
    let a = allocs_for(&make(1000));
    let b = allocs_for(&make(2000));
    (b.saturating_sub(a) + 500) / 1000
}

#[test]
fn native_reads_do_not_allocate() {
    synsema_jit::install();
    native_tier::set_eager(true);
    let prelude = "let xs be [1.5, 2.5, 3.5, 4.5]\nlet grid be [[1, 2], [3, 4]]\nlet m be {\"a\": 1, \"b\": 2.5}\nlet recs be [{\"x\": 1, \"y\": 2}, {\"x\": 3, \"y\": 4}]\nlet s be 0.0\nlet t be 0\n";
    let cases: &[(&str, &str)] = &[
        ("xs[i]", "    set s to s + xs[i % 4]\n"),
        ("xs[-i]", "    set s to s + xs[0 - 1 - i % 4]\n"),
        ("grid[i][j]", "    set t to t + grid[i % 2][(i + 1) % 2]\n"),
        ("m.a y m[\"b\"]", "    set s to s + m.a + m[\"b\"]\n"),
        ("recs[i].x", "    set t to t + recs[i % 2].x + recs[i % 2].y\n"),
    ];
    let before = native_tier::stats();
    let mut bad = Vec::new();
    for (name, body) in cases {
        let n = per_iteration(|n| format!("{}each i in range(0, {})\n{}print([s, t])\n", prelude, n, body));
        if n != 0 {
            bad.push(format!("{}: {} mallocs por vuelta", name, n));
        }
    }
    // `each` sobre una lista.
    let n = per_iteration(|n| format!("{}let ys be range(0, {})\neach y in ys\n    set t to t + y\nprint(t)\n", prelude, n));
    // (armar `ys` con `range` pide su lista: 1 malloc que crece al doble, amortizado; la vuelta, 0)
    if n != 0 {
        bad.push(format!("each sobre una lista: {} mallocs por vuelta", n));
    }
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "los bucles no entraron al código nativo");
    assert!(bad.is_empty(), "{:?}", bad);
}

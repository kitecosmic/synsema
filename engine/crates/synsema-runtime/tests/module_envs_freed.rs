//! Los intérpretes que el host arma desde una foto —uno por item de `parallel_map`, uno por agente
//! lanzado con `spawn`— reconstruyen los módulos que importa el programa. Cada task de un módulo
//! cierra sobre el entorno del módulo y el entorno la tiene en sus bindings: un ciclo de `Rc`. Hasta
//! v0.6.38 nadie lo cortaba y cada item / agente dejaba vivo el módulo entero (lampson: ~26 MB por
//! llamada a `parallel_map`). Este test cuenta los bytes vivos con un allocator propio: al terminar
//! el programa no queda nada, con pocas o con muchas repeticiones.
//!
//! Un solo `#[test]`: el contador es de todo el proceso, dos tests en paralelo se mezclarían.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering::Relaxed};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Relaxed);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static A: Counting = Counting;

/// Bytes que quedan vivos después de correr el programa entero (agentes incluidos).
fn left_alive(src: &str) -> isize {
    let importer = format!("{}/tests/fixtures/module_envs_freed.syn", env!("CARGO_MANIFEST_DIR"));
    let before = LIVE.load(Relaxed);
    let r = synsema_runtime::engine::run_program_ceiled_opts(src, &importer, None, false);
    assert!(r.success, "{:?} {:?}", r.output, r.errors);
    // Los hilos de tokio / del swarm sueltan lo suyo al terminar.
    std::thread::sleep(std::time::Duration::from_millis(300));
    LIVE.load(Relaxed) - before
}

fn parallel_map_program(n: usize) -> String {
    format!(
        "use \"./leak_mod.syn\" as m\nlet total be 0\neach k in range(0, {n})\n    let r be parallel_map((w) => m.salud(w), m.todos(), 4)\n    set total to total + length(r)\nprint(total)\n"
    )
}

/// R2.3: datos globales que cambian en cada vuelta, leídos por `parallel_map` como globales y como
/// items. Se congelan sólo mientras corre cada llamada; si quedaran inmortales, cada vuelta dejaría
/// vivos sus 5000 registros (~1 MB).
fn frozen_scope_program(n: usize) -> String {
    format!(
        "let data be apply(range(0, 5000), (i) => {{\"id\": i, \"nombre\": \"un registro bastante largo \" + text(i)}})
let total be 0
each k in range(0, {n})
    set data to apply(data, (r) => {{\"id\": r.id + 1, \"nombre\": r.nombre + \"!\"}})
    let r be parallel_map((w) => w.id + length(data) + length(w.nombre), data, 4)
    set total to total + length(r)
print(total)
"
    )
}

fn spawn_program(n: usize) -> String {
    format!(
        "use \"./leak_mod.syn\" as m\nagent Worker\n    signal \"done\"\neach k in range(0, {n})\n    spawn Worker\n    wait_for \"done\" timeout 10\nprint(\"ok\")\n"
    )
}

#[test]
fn rebuilt_module_envs_are_freed() {
    // Calentar: lo que el proceso arma una sola vez (pools, tablas) no cuenta.
    let _ = left_alive(&parallel_map_program(1));
    let _ = left_alive(&spawn_program(1));
    let _ = left_alive(&frozen_scope_program(1));
    const MB: isize = 1 << 20;
    for (what, few, many) in [
        ("parallel_map", left_alive(&parallel_map_program(2)), left_alive(&parallel_map_program(12))),
        ("spawn", left_alive(&spawn_program(2)), left_alive(&spawn_program(12))),
        ("parallel_map con datos que cambian", left_alive(&frozen_scope_program(2)), left_alive(&frozen_scope_program(12))),
    ] {
        // Sin el arreglo: ~1 MB por item reconstruido (12 llamadas × 4 items, o 12 agentes).
        assert!(
            few < 2 * MB && many < 2 * MB,
            "{}: quedan vivos {:.1} MB con pocas repeticiones y {:.1} MB con muchas (un módulo reconstruido por item/agente que nadie libera)",
            what,
            few as f64 / MB as f64,
            many as f64 / MB as f64
        );
    }
}

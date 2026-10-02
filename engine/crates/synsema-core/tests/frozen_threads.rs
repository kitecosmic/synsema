//! R2 (specs/modelo-memoria-regiones.md): un valor congelado se lee, se copia y se escribe (copia al
//! escribir) desde varios hilos a la vez, sin tocar el original ni su cuenta.

use std::sync::Arc;

use synsema_core::frozen::{freezable, FrozenValue};
use synsema_core::interpreter::{env_get, Interpreter};
use synsema_core::parser::parse_source;
use synsema_core::types::{ListRef, MapRef, SynValue};

/// Datos con todo lo que se congela: mapas con forma (más de 9 claves: con índice), un mapa en modo
/// diccionario, textos largos, listas anidadas y sin caja, bytes.
const DATA: &str = "\
let filas be apply(range(0, FILAS), (i) => {\"id\": i, \"nombre\": \"un nombre bastante largo \" + text(i), \
\"a\": 1, \"b\": 2, \"c\": 3, \"d\": 4, \"e\": 5, \"f\": 6, \"g\": 7, \"h\": [i, i + 1, i + 2]})
let dic be {}
each i in range(0, CLAVES)
    set dic[\"clave larga número \" + text(i)] to [text(i), i * 2]
let datos be {\"filas\": filas, \"dic\": dic, \"crudo\": bytes(\"hola mundo con bytes\"), \"nums\": range(0, 50)}
";

/// Lo que corre cada hilo: lee todo, y escribe sobre su copia (agrega claves a un mapa de forma
/// congelada, cambia uno, agrega a una lista).
const WORKER: &str = "\
let suma be 0
each f in datos[\"filas\"]
    set suma to suma + f[\"id\"] + f[\"g\"] + f[\"h\"][2] + length(f[\"nombre\"])
let d be datos[\"dic\"]
set suma to suma + length(keys(d)) + d[\"clave larga número 7\"][1]
let fila be datos[\"filas\"][3]
set fila[\"nueva\"] to \"agregada en el hilo\"
set fila[\"a\"] to 100
set datos[\"filas\"][5][\"otra\"] to 1
set datos[\"nums\"] to append(datos[\"nums\"], 99)
let r be suma + fila[\"a\"] + length(keys(fila)) + length(datos[\"nums\"]) + length(keys(datos[\"filas\"][5]))
";

fn global(interp: &Interpreter, name: &str) -> SynValue {
    env_get(&interp.global_env, name).unwrap_or_else(|| panic!("falta {}", name))
}

/// Bajo Miri (que además busca carreras de datos entre los hilos), los mismos datos más chicos.
const FILAS: usize = if cfg!(miri) { 12 } else { 200 };
/// Más de `MAX_SHAPED` (32) claves: modo diccionario.
const CLAVES: usize = if cfg!(miri) { 40 } else { 300 };
const HILOS: usize = if cfg!(miri) { 3 } else { 8 };
const VUELTAS: usize = if cfg!(miri) { 1 } else { 5 };

fn data_source() -> String {
    DATA.replace("FILAS", &FILAS.to_string()).replace("CLAVES", &CLAVES.to_string())
}

fn run_with(datos: SynValue) -> (String, SynValue) {
    let program = parse_source(WORKER, "<worker>").expect("parse");
    let mut interp = Interpreter::new();
    interp.set_global("datos", datos);
    assert!(interp.execute(&program).is_ok(), "el hilo corre: {:?}", interp.output);
    (global(&interp, "r").to_string(), global(&interp, "datos"))
}

#[test]
fn many_threads_read_and_copy_a_frozen_value() {
    let mut main = Interpreter::new();
    assert!(main.execute(&parse_source(&data_source(), "<datos>").expect("parse")).is_ok(), "datos");
    let datos = global(&main, "datos");
    // El resultado de referencia: el mismo programa sobre una copia común, sin congelar.
    let (want, _) = run_with(synsema_core::labels::deep_copy(&datos));
    let before = datos.to_string();

    assert!(freezable(&datos));
    let frozen = Arc::new(FrozenValue::new(datos).ok().expect("se congela"));
    let results: Vec<String> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..HILOS)
            .map(|_| {
                let f = frozen.clone();
                sc.spawn(move || {
                    let mut out = String::new();
                    for _ in 0..VUELTAS {
                        let (r, after) = run_with(f.get());
                        // La copia del hilo cambió; el congelado no.
                        assert_ne!(after.to_string(), f.get().to_string());
                        out = r;
                    }
                    out
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("sin pánico")).collect()
    });
    assert!(results.iter().all(|r| *r == want), "{:?} vs {}", results, want);

    // El original sigue igual e inmortal (su cuenta no se movió con los clones de 8 hilos).
    let v = frozen.get();
    assert_eq!(v.to_string(), before);
    match &v {
        SynValue::Map(m) => {
            assert_eq!(MapRef::strong_count(m), usize::MAX);
            match m.borrow().get("filas") {
                Some(SynValue::List(l)) => assert_eq!(ListRef::strong_count(l), usize::MAX),
                other => panic!("filas: {:?}", other.map(|x| x.type_name())),
            }
        }
        other => panic!("datos: {}", other.type_name()),
    }
}

#[test]
fn what_cannot_be_frozen_is_returned_untouched() {
    let mut i = Interpreter::new();
    let ok = i.execute(&parse_source("task f(x)\n    give x\nlet m be {\"f\": f, \"n\": [1, 2]}\n", "<t>").expect("parse"));
    assert!(ok.is_ok(), "corre");
    let m = global(&i, "m");
    assert!(!freezable(&m));
    let back = FrozenValue::new(m).err().expect("no se congela");
    match &back {
        SynValue::Map(m) => {
            assert_ne!(MapRef::strong_count(m), usize::MAX);
            match m.borrow().get("n") {
                Some(SynValue::List(l)) => assert_ne!(ListRef::strong_count(l), usize::MAX, "no congela a medias"),
                other => panic!("n: {:?}", other.map(|x| x.type_name())),
            }
        }
        other => panic!("{}", other.type_name()),
    }
}

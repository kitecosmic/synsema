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

/// R2.3: congelado con alcance. Los hilos de `run` leen, copian y escriben (copia); al volver, cada
/// objeto tiene la cuenta de antes y deja de ser inmortal.
#[test]
fn a_scoped_freeze_thaws_after_its_threads() {
    use synsema_core::frozen::ScopedFreeze;
    let mut main = Interpreter::new();
    assert!(main.execute(&parse_source(&data_source(), "<datos>").expect("parse")).is_ok(), "datos");
    let datos = global(&main, "datos");
    let (want, _) = run_with(synsema_core::labels::deep_copy(&datos));
    let before = datos.to_string();
    let (map_count, list_count) = match &datos {
        SynValue::Map(m) => match m.borrow().get("filas") {
            Some(SynValue::List(l)) => (MapRef::strong_count(m), ListRef::strong_count(l)),
            _ => panic!("filas"),
        },
        _ => panic!("datos"),
    };

    let mut scope = ScopedFreeze::new();
    let i = scope.add(datos.clone()).expect("se congela");
    let results = scope
        .run(HILOS, 64 << 20, |ctx, _t| {
            let mut last = String::new();
            for _ in 0..VUELTAS {
                let v = ctx.get(i);
                assert!(matches!(&v, SynValue::Map(m) if MapRef::strong_count(m) == usize::MAX), "congelado adentro");
                // Lo congelado con alcance no puede pasar a una región permanente.
                assert!(FrozenValue::new(v.clone()).is_err());
                // Un `run` anidado lo comparte tal cual (termina antes que éste).
                let mut inner = ScopedFreeze::new();
                let j = inner.add(v.clone()).expect("lo de afuera sirve adentro");
                let n = inner.run(2, 64 << 20, |c, _| c.get(j).to_string().len()).expect("anidado");
                assert_eq!(n[0], n[1]);
                last = run_with(v).0;
            }
            last
        })
        .expect("hilos");
    assert!(results.iter().all(|r| *r == want), "{:?} vs {}", results, want);

    // Descongelado: las cuentas de antes (más el clon que guardó `add`, ya soltado), mortal.
    assert_eq!(datos.to_string(), before);
    match &datos {
        SynValue::Map(m) => {
            assert_eq!(MapRef::strong_count(m), map_count);
            match m.borrow().get("filas") {
                Some(SynValue::List(l)) => assert_eq!(ListRef::strong_count(l), list_count),
                _ => panic!("filas"),
            }
        }
        _ => panic!("datos"),
    }
    // Y se puede escribir en el lugar otra vez (único dueño de la lista de adentro: no copia).
    let program = parse_source("set datos[\"nums\"] to append(datos[\"nums\"], 1)\n", "<w>").expect("parse");
    main.set_global("datos", datos);
    assert!(main.execute(&program).is_ok());
}

#[test]
fn a_panicking_thread_still_thaws() {
    use synsema_core::frozen::ScopedFreeze;
    let mut i = Interpreter::new();
    assert!(i.execute(&parse_source("let l be [[1, 2], \"un texto largo que vive en el montón\"]\n", "<p>").expect("parse")).is_ok());
    let l = global(&i, "l");
    let before = match &l {
        SynValue::List(x) => ListRef::strong_count(x),
        _ => panic!("l"),
    };
    let mut scope = ScopedFreeze::new();
    let k = scope.add(l.clone()).expect("se congela");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scope.run(2, 64 << 20, |ctx, t| {
            let _v = ctx.get(k);
            if t == 1 {
                panic!("a propósito");
            }
        })
    }));
    assert!(r.is_err(), "el pánico sigue");
    match &l {
        SynValue::List(x) => {
            assert_eq!(ListRef::strong_count(x), before);
            assert!(!ListRef::is_immortal(x));
        }
        _ => panic!("l"),
    }
}

/// R2.4: `share` sólo toma lo que ya es permanente; ni lo mortal ni lo congelado con alcance.
#[test]
fn share_takes_only_what_is_already_permanent() {
    use synsema_core::frozen::ScopedFreeze;
    let mut i = Interpreter::new();
    assert!(i.execute(&parse_source("let a be [[1], \"un texto largo que vive en el montón\"]
let b be [[2]]
", "<s>").expect("parse")).is_ok());
    let a = global(&i, "a");
    let b = global(&i, "b");
    assert!(FrozenValue::share(a.clone()).is_err(), "mortal: no");
    let _keep = FrozenValue::new(a.clone()).ok().expect("se congela");
    assert!(FrozenValue::share(a.clone()).is_ok(), "permanente: sí");
    let mut scope = ScopedFreeze::new();
    let k = scope.add(b.clone()).expect("se congela con alcance");
    let shared = scope
        .run(1, 64 << 20, |ctx, _| FrozenValue::share(ctx.get(k)).is_ok())
        .expect("hilo");
    assert_eq!(shared, vec![false], "con alcance: no");
    assert!(FrozenValue::share(SynValue::Number(synsema_core::number::Number::Int(1))).is_ok());
}

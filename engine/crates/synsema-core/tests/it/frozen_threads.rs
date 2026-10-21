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

/// R2.5: el registro de módulos une mapa y entorno por DIRECCIÓN. Si un entorno muere mientras su
/// mapa sigue vivo (por ejemplo, congelado en una foto) y un entorno nuevo cae en la misma
/// dirección, el nuevo no puede heredar el mapa ajeno (antes: un worker escribía sus exportaciones
/// en el mapa de otro módulo, o entraba en pánico si estaba congelado).
#[test]
fn a_new_environment_never_inherits_a_dead_modules_map() {
    use synsema_core::interpreter::{module_map_of_env, register_module, Environment};
    let i = Interpreter::new();
    let genv = i.global_env.clone();
    let mut maps = Vec::new();
    // Muchos módulos (para que el registro se limpie) cuyos entornos mueren y cuyos mapas quedan.
    for k in 0..200 {
        let env = Environment::child(&genv, &format!("module:m{}", k));
        let map = synsema_core::types::SynMap::new().into_ref();
        register_module(&map, &env);
        if k % 2 == 0 {
            MapRef::make_immortal(&map);
        }
        maps.push(map);
        drop(env);
    }
    // Entornos nuevos: el allocator reusa direcciones de los muertos.
    let mut fresh = Vec::new();
    for k in 0..400 {
        let env = Environment::child(&genv, &format!("module:nuevo{}", k));
        assert!(module_map_of_env(&env).is_none(), "un entorno nuevo heredó el mapa de un módulo muerto");
        fresh.push(env);
    }
}

/// Auditoría de R2: leer nunca escribe un valor congelado. Listas sin caja (`range`, floats), listas
/// de valores y mapas, congeladas, leídas desde varios hilos con las operaciones de lectura del
/// intérprete de core. (El pánico que encontró la auditoría —`list_values` pasaba una lista sin caja
/// a valores en el lugar— se ve con los builtins del runtime: lo reproduce
/// `synsema-runtime/tests/frozen_reads.rs`; éste cubre los caminos de core.)
#[test]
fn reading_frozen_unboxed_lists_never_writes() {
    use synsema_core::frozen::ScopedFreeze;
    let mut main = Interpreter::new();
    let src = "let IDS be range(0, 100)\nlet FL be [1.5, 2.5, 3.5]\nlet VS be [\"a\", \"b\", 3]\nlet M be {\"ids\": range(0, 5), \"n\": 1}\n";
    assert!(main.execute(&parse_source(src, "<g>").expect("parse")).is_ok());
    let names = ["IDS", "FL", "VS", "M"];
    let vals: Vec<SynValue> = names.iter().map(|n| global(&main, n)).collect();
    // `IDS` es sin caja (8 B por elemento): el caso que entraba en pánico.
    assert!(matches!(&vals[0], SynValue::List(l) if !l.borrow().is_values()));
    const READS: &str = "\
task lee()
    let r be []
    set r to append(r, count(IDS))
    set r to append(r, length(IDS))
    set r to append(r, 5 in IDS)
    set r to append(r, 500 in IDS)
    set r to append(r, length(IDS + IDS))
    set r to append(r, mean(FL))
    set r to append(r, sum(IDS))
    set r to append(r, min(IDS))
    set r to append(r, max(FL))
    set r to append(r, IDS[3])
    set r to append(r, FL[-1])
    set r to append(r, length(sort(IDS)))
    set r to append(r, length(reverse(IDS)))
    set r to append(r, length(unique(IDS)))
    set r to append(r, length(apply(IDS, (x) => x * 2)))
    set r to append(r, length(where(IDS, (x) => x > 50)))
    set r to append(r, reduce(IDS, (a, x) => a + x, 0))
    set r to append(r, text(FL))
    set r to append(r, join(VS, \",\"))
    set r to append(r, index_of(IDS, 42))
    set r to append(r, length(slice(IDS, 10, 20)))
    set r to append(r, IDS == IDS)
    set r to append(r, count(M[\"ids\"]))
    set r to append(r, 3 in M[\"ids\"])
    set r to append(r, length(keys(M)))
    set r to append(r, length(values(M)))
    each x in IDS
        set r to append(r, x)
    each x in FL
        set r to append(r, x)
    give r
let r be lee()
";
    let program = parse_source(READS, "<reads>").expect("parse");
    let run = |vals: &[SynValue]| -> String {
        let mut w = Interpreter::new();
        for (n, v) in names.iter().zip(vals) {
            w.set_global(n, v.clone());
        }
        if let Err(synsema_core::interpreter::Control::Error(e)) = w.execute(&program) {
            panic!("falló: {} {:?}", e.message, e.location);
        }
        global(&w, "r").to_string()
    };
    let want = run(&vals.iter().map(synsema_core::labels::deep_copy).collect::<Vec<_>>());
    let mut scope = ScopedFreeze::new();
    let idx: Vec<usize> = vals.iter().map(|v| scope.add(v.clone()).expect("se congela")).collect();
    let got = scope
        .run(HILOS, 64 << 20, |ctx, _| run(&idx.iter().map(|i| ctx.get(*i)).collect::<Vec<_>>()))
        .expect("hilos");
    assert!(got.iter().all(|g| *g == want), "{:?} vs {}", got, want);
    // Y para siempre (como las globales de `serve`).
    let frozen: Vec<FrozenValue> = vals.iter().map(|v| FrozenValue::new(v.clone()).ok().expect("se congela")).collect();
    assert_eq!(run(&frozen.iter().map(|f| f.get()).collect::<Vec<_>>()), want);
}

/// Auditoría de R2, hallazgo 1: un mapa propio que comparte la forma y las claves con un mapa congelado
/// CON ALCANCE (una copia hecha dentro del `run`) no puede pasar a la región permanente: esas partes se
/// descongelan al terminar.
#[test]
fn a_map_sharing_a_scoped_shape_cannot_become_permanent() {
    use synsema_core::frozen::ScopedFreeze;
    let mut i = Interpreter::new();
    assert!(i.execute(&parse_source("let m be {\"nombre largo de una clave\": 1, \"otra clave bastante larga\": 2}\n", "<m>").expect("parse")).is_ok());
    let m = global(&i, "m");
    let mut scope = ScopedFreeze::new();
    let k = scope.add(m.clone()).expect("se congela");
    let res = scope
        .run(1, 64 << 20, |ctx, _| {
            let SynValue::Map(fm) = ctx.get(k) else { panic!("mapa") };
            // Copia propia: forma y claves compartidas con el congelado con alcance.
            let copy = SynValue::Map(fm.borrow().to_ref());
            (FrozenValue::new(copy).is_err(), synsema_core::frozen::freezable(&ctx.get(k)))
        })
        .expect("hilo");
    assert_eq!(res, vec![(true, false)]);
    // Fuera del alcance, ya descongelado: el mismo mapa se congela sin problema.
    assert!(FrozenValue::new(m).is_ok());
}

/// Auditoría de R2, hallazgo 4: congelar algo que alguien tiene prestado se rechaza (vuelve intacto)
/// en vez de entrar en pánico a mitad del congelado.
#[test]
fn freezing_a_borrowed_value_is_refused_not_a_panic() {
    use synsema_core::frozen::ScopedFreeze;
    let mut i = Interpreter::new();
    assert!(i.execute(&parse_source("let l be [[1, 2], {\"a\": [3]}]\n", "<l>").expect("parse")).is_ok());
    let l = global(&i, "l");
    let SynValue::List(outer) = &l else { panic!("lista") };
    let inner = outer.borrow().get(0).expect("primero");
    let SynValue::List(inner_list) = inner else { panic!("lista") };
    {
        let _reading = inner_list.borrow();
        assert!(FrozenValue::new(l.clone()).is_err());
        assert!(ScopedFreeze::new().add(l.clone()).is_err());
    }
    assert!(!ListRef::is_frozen(outer) && !ListRef::is_frozen(&inner_list), "no congeló a medias");
    assert!(FrozenValue::new(l).is_ok(), "sin el préstamo, sí");
}

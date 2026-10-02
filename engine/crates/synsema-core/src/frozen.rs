//! Valores congelados: la región compartida (R2 de specs/modelo-memoria-regiones.md).
//!
//! Congelar vuelve inmortal, **en el lugar y sin copiar**, todo lo que un valor alcanza: listas,
//! mapas (con sus formas, claves e índices), textos, bytes, arrays, fechas, secretos y valores del
//! servidor. Un inmortal no se escribe: clonarlo y soltarlo no tocan su cuenta, leerlo no toca su
//! bandera de préstamo, y escribirlo copia primero (su cuenta es `usize::MAX`, así que
//! `make_unique` lo ve compartido). Una forma de mapa congelada tampoco guarda transiciones nuevas:
//! van a una tabla por hilo (`synmap::frozen_transition`). Por eso lo congelado se lee desde varios
//! hilos a la vez, una sola copia para todos (antes, `to_send`/`from_send`: una por hilo).
//!
//! Dos formas:
//! - **Para siempre** (`FrozenValue`, R2.2): lo que vive lo que el proceso (las globales del
//!   preámbulo de `serve`). Un inmortal no se libera nunca.
//! - **Con alcance** (`ScopedFreeze`, R2.3): lo que sólo hace falta mientras corren unos hilos
//!   (`parallel_map`, que toma las globales en CADA llamada: congelarlas para siempre sería una
//!   fuga). `ScopedFreeze::run` congela anotando la cuenta de cada objeto, corre los hilos, espera a
//!   cada uno (con sus `thread_local`), le devuelve a cada objeto su cuenta y recién ahí los suelta.
//!   Lo congelado con alcance lleva otra marca (`is_scoped`) y no puede pasar a un `FrozenValue`.
//!
//! Lo que no se puede congelar se rechaza entero (el valor vuelve intacto) y sigue por el camino de
//! antes: las tareas y los builtins (cuelgan de entornos con `Rc<RefCell>`), los privados (su
//! etiqueta es un `Rc` de la biblioteca estándar), las páginas perezosas del servidor (una
//! función), los mapas que son la vista de un módulo (se escriben en el lugar) y lo congelado con
//! alcance (para `FrozenValue`).
//!
//! Invariante de los `unsafe impl Send/Sync` (sólo este archivo arma un `FrozenValue` o un
//! `ScopeCtx`): todo lo alcanzable es inmortal y nada de eso se escribe mientras otro hilo lo pueda
//! ver. Los únicos datos que no son objetos del montón son copias (números, `Box` de enteros grandes,
//! bytes en línea de un texto corto) que cada hilo sólo lee.

use std::collections::HashSet;

use synsema_heap::FreezeLog;
use synsema_text::{SynText, TextThaw};

use crate::types::{BytesRef, ListRef, MapRef, Obj, ServerValue, SynValue};

/// Un valor congelado para siempre: se lee (y se clona) desde cualquier hilo. Ver el módulo.
pub struct FrozenValue(SynValue);

// SAFETY: ver el módulo. Todo lo que el valor alcanza es inmortal PERMANENTE y no se escribe:
// clonar, leer y soltar desde otro hilo sólo leen cabeceras que no cambian, y escribir copia
// primero. `new` es el único constructor, congela todo antes de armarlo y rechaza lo que tiene
// alcance (se descongelaría mientras otro hilo todavía lo lee).
unsafe impl Send for FrozenValue {}
// SAFETY: ídem: `&FrozenValue` sólo da `get` (un clon, que no escribe nada compartido).
unsafe impl Sync for FrozenValue {}

impl FrozenValue {
    /// Congela `v` en el lugar, para siempre. `Err(v)` (sin tocar nada) si alcanza algo que no se
    /// puede congelar. En un punto quieto: nadie puede tener prestada una lista o un mapa de `v`.
    pub fn new(v: SynValue) -> Result<FrozenValue, SynValue> {
        if !freezable(&v) {
            return Err(v);
        }
        mark(&v, &mut Marker { log: None });
        Ok(FrozenValue(v))
    }

    /// El valor, para atarlo en el hilo que lo pide: un clon que no escribe nada compartido.
    #[inline]
    pub fn get(&self) -> SynValue {
        self.0.clone()
    }
}

/// ¿Se puede congelar para siempre todo lo que alcanza `v`? (Lo ya congelado para siempre, sí; lo
/// congelado con alcance, no: se descongelaría mientras otro hilo lo sigue leyendo.)
pub fn freezable(v: &SynValue) -> bool {
    can(v, &mut HashSet::new(), false)
}

fn can(v: &SynValue, seen: &mut HashSet<usize>, scoped_ok: bool) -> bool {
    match v {
        SynValue::Number(_) | SynValue::Bool(_) | SynValue::Nothing | SynValue::Complex(_) => true,
        SynValue::Text(t) => scoped_ok || !t.is_scoped(),
        SynValue::Bytes(b) => scoped_ok || !BytesRef::is_scoped(b),
        SynValue::Array(a) => scoped_ok || !Obj::is_scoped(a),
        SynValue::Time(t) => scoped_ok || !Obj::is_scoped(t),
        SynValue::Secret(s) => scoped_ok || !Obj::is_scoped(s),
        SynValue::List(l) => {
            if !scoped_ok && ListRef::is_scoped(l) {
                return false;
            }
            if ListRef::is_immortal(l) || !seen.insert(ListRef::as_ptr(l) as usize) {
                return true;
            }
            let b = l.borrow();
            b.as_values().is_none_or(|vs| vs.iter().all(|x| can(x, seen, scoped_ok)))
        }
        SynValue::Map(m) => can_map(m, seen, scoped_ok),
        SynValue::Server(s) => {
            if !scoped_ok && Obj::is_scoped(s) {
                return false;
            }
            match &**s {
                ServerValue::Raw { .. } | ServerValue::RawBytes { .. } | ServerValue::Redirect { .. } => true,
                ServerValue::Envelope { value, .. } => can(value, seen, scoped_ok),
                ServerValue::Node(m) => can_map(m, seen, scoped_ok),
                ServerValue::Content(b) => can(b, seen, scoped_ok),
                ServerValue::WithHeaders { inner, .. } => can(inner, seen, scoped_ok),
                ServerValue::Paged(_) => false,
            }
        }
        SynValue::Task(_) | SynValue::Builtin(_) | SynValue::Private(_) => false,
    }
}

fn can_map(m: &MapRef, seen: &mut HashSet<usize>, scoped_ok: bool) -> bool {
    if !scoped_ok && MapRef::is_scoped(m) {
        return false;
    }
    if MapRef::is_immortal(m) || !seen.insert(MapRef::as_ptr(m).cast::<()>() as usize) {
        return true;
    }
    // La vista de un módulo (`use … as m`) se escribe en el lugar (`set m.X[k]`): no se congela.
    if crate::interpreter::module_env_of_map(m).is_some() {
        return false;
    }
    let b = m.borrow();
    b.values().all(|x| can(x, seen, scoped_ok))
}

/// Lo que un congelado con alcance volvió inmortal (objetos del montón y textos), para devolverles
/// la cuenta.
#[derive(Default)]
struct ThawLog {
    heap: FreezeLog,
    texts: Vec<TextThaw>,
}

/// Cómo se vuelve inmortal cada objeto: para siempre (`log: None`) o anotándolo para descongelar.
pub(crate) struct Marker<'a> {
    log: Option<&'a mut ThawLog>,
}

impl Marker<'_> {
    pub(crate) fn text(&mut self, t: &SynText) {
        match &mut self.log {
            None => t.make_immortal(),
            Some(log) => log.texts.extend(t.make_immortal_logged()),
        }
    }
    pub(crate) fn obj<T>(&mut self, o: &Obj<T>) {
        match &mut self.log {
            None => Obj::make_immortal(o),
            Some(log) => Obj::make_immortal_logged(o, &mut log.heap),
        }
    }
    fn bytes(&mut self, b: &BytesRef) {
        match &mut self.log {
            None => BytesRef::make_immortal(b),
            Some(log) => BytesRef::make_immortal_logged(b, &mut log.heap),
        }
    }
    fn list(&mut self, l: &ListRef) {
        match &mut self.log {
            None => ListRef::make_immortal(l),
            Some(log) => ListRef::make_immortal_logged(l, &mut log.heap),
        }
    }
    fn map(&mut self, m: &MapRef) {
        match &mut self.log {
            None => MapRef::make_immortal(m),
            Some(log) => MapRef::make_immortal_logged(m, &mut log.heap),
        }
    }
}

/// Vuelve inmortal todo lo que alcanza `v` (ya verificado con `freezable`). Lo ya inmortal se salta:
/// un subárbol compartido se recorre una vez.
fn mark(v: &SynValue, mk: &mut Marker) {
    match v {
        SynValue::Text(t) => mk.text(t),
        SynValue::Bytes(b) => mk.bytes(b),
        SynValue::Array(a) => mk.obj(a),
        SynValue::Time(t) => mk.obj(t),
        SynValue::Secret(s) => mk.obj(s),
        SynValue::List(l) => {
            if ListRef::is_immortal(l) {
                return;
            }
            if let Some(vs) = l.borrow().as_values() {
                vs.iter().for_each(|x| mark(x, mk));
            }
            mk.list(l);
        }
        SynValue::Map(m) => mark_map(m, mk),
        SynValue::Server(s) => {
            if Obj::is_immortal(s) {
                return;
            }
            match &**s {
                ServerValue::Envelope { value, .. } => mark(value, mk),
                ServerValue::Node(m) => mark_map(m, mk),
                ServerValue::Content(b) => mark(b, mk),
                ServerValue::WithHeaders { inner, .. } => mark(inner, mk),
                ServerValue::Raw { .. } | ServerValue::RawBytes { .. } | ServerValue::Redirect { .. } => {}
                ServerValue::Paged(_) => unreachable!("freezable lo rechaza"),
            }
            mk.obj(s);
        }
        SynValue::Number(_) | SynValue::Bool(_) | SynValue::Nothing | SynValue::Complex(_) => {}
        SynValue::Task(_) | SynValue::Builtin(_) | SynValue::Private(_) => unreachable!("freezable lo rechaza"),
    }
}

fn mark_map(m: &MapRef, mk: &mut Marker) {
    if MapRef::is_immortal(m) {
        return;
    }
    {
        let b = m.borrow();
        for (k, x) in b.iter() {
            mk.text(k.text());
            mark(x, mk);
        }
        crate::synmap::freeze_layout(&b, mk);
    }
    mk.map(m);
}

/// Valores que se congelan sólo mientras corren unos hilos (R2.3, ver el módulo).
///
/// `add` sólo revisa: congelar, correr, esperar, descongelar y soltar pasan todos dentro de `run`,
/// donde el hilo que llama no hace nada más. Así nadie clona lo congelado fuera de los hilos de
/// `run` (un clon hecho mientras es inmortal no cuenta, y si sobreviviera al descongelado, soltarlo
/// después liberaría antes de tiempo).
#[derive(Default)]
pub struct ScopedFreeze {
    values: Vec<SynValue>,
}

/// Lo congelado, para los hilos de `ScopedFreeze::run`: `get(i)` da un clon del valor `i`.
pub struct ScopeCtx {
    values: Vec<SynValue>,
}

// SAFETY: ver el módulo. Un `ScopeCtx` sólo existe dentro de `ScopedFreeze::run`, después de congelar
// todos sus valores y antes de descongelarlos, y los hilos lo reciben prestado (`&ScopeCtx`, que no
// puede salir del alcance de `run`). Mientras tanto nada de lo que alcanza se escribe: el hilo que
// llamó está dentro de `run`, y los demás sólo clonan, leen y sueltan (que no escriben un inmortal).
unsafe impl Sync for ScopeCtx {}

impl ScopeCtx {
    /// Un clon del valor `i` (el índice que dio `ScopedFreeze::add`).
    #[inline]
    pub fn get(&self, i: usize) -> SynValue {
        self.values[i].clone()
    }
}

impl ScopedFreeze {
    pub fn new() -> ScopedFreeze {
        ScopedFreeze::default()
    }

    /// `Ok(i)` si `v` se puede congelar: dentro de `run`, `ScopeCtx::get(i)`. `Err(v)` si no (sigue
    /// por el camino de siempre). Todavía no congela nada.
    pub fn add(&mut self, v: SynValue) -> Result<usize, SynValue> {
        // Lo congelado con alcance por un `run` de más afuera sirve tal cual: este `run` termina antes
        // (corre dentro de un hilo de aquél), así que no se descongela mientras éste lo lee.
        if !can(&v, &mut HashSet::new(), true) {
            return Err(v);
        }
        self.values.push(v);
        Ok(self.values.len() - 1)
    }

    /// Congela lo agregado, corre `work(ctx, t)` en `threads` hilos (`t` = 0..threads, con `stack`
    /// bytes de pila), espera a cada uno, descongela y suelta. Devuelve lo que dio cada hilo, en
    /// orden. Si un hilo entra en pánico, el pánico sigue después de descongelar; si un hilo no se
    /// pudo crear, el error vuelve después de esperar a los demás.
    pub fn run<T: Send>(
        self,
        threads: usize,
        stack: usize,
        work: impl Fn(&ScopeCtx, usize) -> T + Sync,
    ) -> std::io::Result<Vec<T>> {
        let ctx = ScopeCtx { values: self.values };
        let mut log = ThawLog::default();
        {
            let mut mk = Marker { log: Some(&mut log) };
            for v in &ctx.values {
                // Dos valores pueden compartir partes: lo ya inmortal (de esta vuelta o de antes) se
                // salta. Uno ya congelado con alcance no llega acá (`add` lo rechaza).
                mark(v, &mut mk);
            }
        }
        let joined: Vec<std::thread::Result<T>>;
        let spawn_error: Option<std::io::Error>;
        {
            let ctx = &ctx;
            let work = &work;
            let (results, err) = std::thread::scope(|sc| {
                let mut handles = Vec::with_capacity(threads);
                let mut err = None;
                for t in 0..threads {
                    match std::thread::Builder::new().stack_size(stack).spawn_scoped(sc, move || work(ctx, t)) {
                        Ok(h) => handles.push(h),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                // `join` explícito: espera a que cada hilo termine del todo, con sus `thread_local`
                // (la espera implícita de `scope` vuelve antes de que corran sus destructores).
                (handles.into_iter().map(|h| h.join()).collect::<Vec<_>>(), err)
            });
            joined = results;
            spawn_error = err;
        }
        // SAFETY: los hilos que vieron lo congelado terminaron (esperados arriba, con sus
        // `thread_local`); un clon que hicieron no salió de ellos (`SynValue` no es `Send`), así que ya
        // se soltó (o se olvidó, y entonces no se suelta nunca: no cuenta). El hilo que llamó no clonó
        // nada desde que se congeló. Los objetos siguen vivos: `ctx` los sostiene.
        unsafe {
            log.heap.thaw();
            for t in log.texts {
                t.thaw();
            }
        }
        drop(ctx);
        if let Some(e) = spawn_error {
            return Err(e);
        }
        let mut out = Vec::with_capacity(joined.len());
        for r in joined {
            match r {
                Ok(v) => out.push(v),
                Err(p) => std::panic::resume_unwind(p),
            }
        }
        Ok(out)
    }
}

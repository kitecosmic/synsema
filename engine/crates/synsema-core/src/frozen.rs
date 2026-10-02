//! Valores congelados: la región compartida (R2 de specs/modelo-memoria-regiones.md).
//!
//! `FrozenValue::new` vuelve inmortal, **en el lugar y sin copiar**, todo lo que un valor alcanza:
//! listas, mapas (con sus formas, claves e índices), textos, bytes, arrays, fechas, secretos y
//! valores del servidor. Un inmortal no se escribe nunca más: clonarlo y soltarlo no tocan su
//! cuenta, leerlo no toca su bandera de préstamo, y escribirlo copia primero (la cuenta de un
//! inmortal es `usize::MAX`, así que `make_unique` lo ve compartido). Una forma de mapa congelada
//! tampoco guarda transiciones nuevas: van a una tabla por hilo (`synmap::frozen_transition`).
//!
//! Por eso un `FrozenValue` se puede leer desde varios hilos a la vez (`Send + Sync`): `serve`,
//! `parallel_map`, los agentes y `cron` reciben las globales así, una sola vez para todos sus
//! hilos, en vez de una copia por hilo (`to_send`/`from_send`).
//!
//! Lo que no se puede congelar se rechaza entero (`Err` con el valor intacto) y sigue por el
//! camino de antes: las tareas y los builtins (cuelgan de entornos con `Rc<RefCell>`), los
//! privados (su etiqueta es un `Rc` de la biblioteca estándar), las páginas perezosas del
//! servidor (una función) y los mapas que son la vista de un módulo (se escriben en el lugar).
//!
//! Invariante del `unsafe impl Send/Sync` (lo establece este archivo y nadie más arma un
//! `FrozenValue`): todo lo alcanzable desde el valor es inmortal, y nada de eso se escribe desde que
//! se congeló. Los únicos datos que no son objetos del montón son copias (números, `Box` de enteros
//! grandes, bytes en línea de un texto corto) que cada hilo sólo lee.

use std::collections::HashSet;

use crate::types::{BytesRef, ListRef, MapRef, Obj, ServerValue, SynValue};

/// Un valor congelado: se lee (y se clona) desde cualquier hilo. Ver el módulo.
pub struct FrozenValue(SynValue);

// SAFETY: ver el módulo. Todo lo que el valor alcanza es inmortal y no se escribe: clonar, leer y
// soltar desde otro hilo sólo leen cabeceras que no cambian (la cuenta en el tope, la bandera de
// préstamo en el tope), y escribir copia primero. `new` es el único constructor y congela todo
// antes de armarlo.
unsafe impl Send for FrozenValue {}
// SAFETY: ídem: `&FrozenValue` sólo da `get` (un clon, que no escribe nada compartido).
unsafe impl Sync for FrozenValue {}

impl FrozenValue {
    /// Congela `v` en el lugar. `Err(v)` (sin tocar nada) si alcanza algo que no se puede congelar.
    /// Hay que llamarlo en un punto quieto: nadie puede tener prestada una lista o un mapa de `v`.
    pub fn new(v: SynValue) -> Result<FrozenValue, SynValue> {
        if !freezable(&v) {
            return Err(v);
        }
        mark(&v);
        Ok(FrozenValue(v))
    }

    /// El valor, para atarlo en el hilo que lo pide: un clon que no escribe nada compartido.
    #[inline]
    pub fn get(&self) -> SynValue {
        self.0.clone()
    }
}

/// ¿Se puede congelar todo lo que alcanza `v`?
pub fn freezable(v: &SynValue) -> bool {
    can(v, &mut HashSet::new())
}

fn can(v: &SynValue, seen: &mut HashSet<usize>) -> bool {
    match v {
        SynValue::Number(_)
        | SynValue::Text(_)
        | SynValue::Bool(_)
        | SynValue::Nothing
        | SynValue::Complex(_)
        | SynValue::Bytes(_)
        | SynValue::Array(_)
        | SynValue::Time(_)
        | SynValue::Secret(_) => true,
        SynValue::List(l) => {
            if ListRef::is_immortal(l) || !seen.insert(ListRef::as_ptr(l) as usize) {
                return true;
            }
            let b = l.borrow();
            b.as_values().is_none_or(|vs| vs.iter().all(|x| can(x, seen)))
        }
        SynValue::Map(m) => can_map(m, seen),
        SynValue::Server(s) => match &**s {
            ServerValue::Raw { .. } | ServerValue::RawBytes { .. } | ServerValue::Redirect { .. } => true,
            ServerValue::Envelope { value, .. } => can(value, seen),
            ServerValue::Node(m) => can_map(m, seen),
            ServerValue::Content(b) => can(b, seen),
            ServerValue::WithHeaders { inner, .. } => can(inner, seen),
            ServerValue::Paged(_) => false,
        },
        SynValue::Task(_) | SynValue::Builtin(_) | SynValue::Private(_) => false,
    }
}

fn can_map(m: &MapRef, seen: &mut HashSet<usize>) -> bool {
    if MapRef::is_immortal(m) || !seen.insert(MapRef::as_ptr(m).cast::<()>() as usize) {
        return true;
    }
    // La vista de un módulo (`use … as m`) se escribe en el lugar (`set m.X[k]`): no se congela.
    if crate::interpreter::module_env_of_map(m).is_some() {
        return false;
    }
    let b = m.borrow();
    b.values().all(|x| can(x, seen))
}

/// Vuelve inmortal todo lo que alcanza `v` (ya verificado con `freezable`). Lo ya inmortal se salta:
/// un subárbol compartido se recorre una vez.
fn mark(v: &SynValue) {
    match v {
        SynValue::Text(t) => t.make_immortal(),
        SynValue::Bytes(b) => BytesRef::make_immortal(b),
        SynValue::Array(a) => Obj::make_immortal(a),
        SynValue::Time(t) => Obj::make_immortal(t),
        SynValue::Secret(s) => Obj::make_immortal(s),
        SynValue::List(l) => {
            if ListRef::is_immortal(l) {
                return;
            }
            if let Some(vs) = l.borrow().as_values() {
                vs.iter().for_each(mark);
            }
            ListRef::make_immortal(l);
        }
        SynValue::Map(m) => mark_map(m),
        SynValue::Server(s) => {
            if Obj::is_immortal(s) {
                return;
            }
            match &**s {
                ServerValue::Envelope { value, .. } => mark(value),
                ServerValue::Node(m) => mark_map(m),
                ServerValue::Content(b) => mark(b),
                ServerValue::WithHeaders { inner, .. } => mark(inner),
                ServerValue::Raw { .. } | ServerValue::RawBytes { .. } | ServerValue::Redirect { .. } => {}
                ServerValue::Paged(_) => unreachable!("freezable lo rechaza"),
            }
            Obj::make_immortal(s);
        }
        SynValue::Number(_) | SynValue::Bool(_) | SynValue::Nothing | SynValue::Complex(_) => {}
        SynValue::Task(_) | SynValue::Builtin(_) | SynValue::Private(_) => unreachable!("freezable lo rechaza"),
    }
}

fn mark_map(m: &MapRef) {
    if MapRef::is_immortal(m) {
        return;
    }
    {
        let b = m.borrow();
        for (k, x) in b.iter() {
            k.make_immortal();
            mark(x);
        }
        crate::synmap::freeze_layout(&b);
    }
    MapRef::make_immortal(m);
}

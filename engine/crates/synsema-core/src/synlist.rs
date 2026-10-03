//! El cuerpo de una lista (F4.8e de specs/compute-rendimiento.md): `ListRef` es
//! `Rc<RefCell<SynList>>`. Una lista de enteros o de floats guarda sus números sin caja (8 bytes por
//! elemento en vez de los 24 de un `SynValue`), como los "elements kinds" de V8; cualquier otra cosa,
//! valores. La transición es de una sola vía: lo que necesita los elementos como `SynValue` (casi todo
//! el código genérico) pide `list_values`, que la pasa a valores para siempre. Lo observable es lo
//! mismo en las tres: el orden, la igualdad, el texto, el copy-on-write (lo hace el `Rc`).

use synsema_heap::{Ref, RefMut};
use std::fmt;

use crate::number::Number;
use crate::types::{ListRef, SynValue};

/// Los elementos de una lista.
#[derive(Clone)]
pub struct SynList(Repr);

/// Un elemento sin copiarlo: el valor donde vive, o el número sin caja.
pub enum Elem<'a> {
    Value(&'a SynValue),
    Int(i64),
    Float(f64),
}

#[derive(Clone)]
enum Repr {
    Values(Vec<SynValue>),
    /// Todos `Number::Int`.
    Ints(Vec<i64>),
    /// Todos `Number::Float`.
    Floats(Vec<f64>),
}

impl Default for SynList {
    fn default() -> SynList {
        SynList::new()
    }
}

impl SynList {
    pub fn new() -> SynList {
        SynList(Repr::Values(Vec::new()))
    }

    pub fn with_capacity(n: usize) -> SynList {
        SynList(Repr::Values(Vec::with_capacity(n)))
    }

    /// Una lista de enteros sin caja.
    pub fn from_ints(v: Vec<i64>) -> SynList {
        SynList(Repr::Ints(v))
    }

    /// Una lista de floats sin caja.
    pub fn from_floats(v: Vec<f64>) -> SynList {
        SynList(Repr::Floats(v))
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.0 {
            Repr::Values(v) => v.len(),
            Repr::Ints(v) => v.len(),
            Repr::Floats(v) => v.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Si guarda valores (no números sin caja).
    #[inline]
    pub fn is_values(&self) -> bool {
        matches!(self.0, Repr::Values(_))
    }

    /// El elemento `i` sin copiarlo.
    #[inline]
    pub fn elem(&self, i: usize) -> Option<Elem<'_>> {
        match &self.0 {
            Repr::Values(v) => v.get(i).map(Elem::Value),
            Repr::Ints(v) => v.get(i).map(|x| Elem::Int(*x)),
            Repr::Floats(v) => v.get(i).map(|x| Elem::Float(*x)),
        }
    }

    /// El elemento `i` (una copia: los números sin caja no tienen un `SynValue` adentro).
    #[inline]
    pub fn get(&self, i: usize) -> Option<SynValue> {
        match &self.0 {
            Repr::Values(v) => v.get(i).cloned(),
            Repr::Ints(v) => v.get(i).map(|x| SynValue::Number(Number::Int(*x))),
            Repr::Floats(v) => v.get(i).map(|x| SynValue::Number(Number::Float(*x))),
        }
    }

    /// Los enteros, si es una lista de enteros sin caja.
    pub fn as_ints(&self) -> Option<&[i64]> {
        match &self.0 {
            Repr::Ints(v) => Some(v),
            _ => None,
        }
    }

    /// Los floats, si es una lista de floats sin caja.
    pub fn as_floats(&self) -> Option<&[f64]> {
        match &self.0 {
            Repr::Floats(v) => Some(v),
            _ => None,
        }
    }

    /// Los valores, si ya los guarda como valores.
    #[inline]
    pub fn as_values(&self) -> Option<&Vec<SynValue>> {
        match &self.0 {
            Repr::Values(v) => Some(v),
            _ => None,
        }
    }

    /// Los valores, para cambiarlos: una lista sin caja pasa a valores (para siempre).
    pub fn values_mut(&mut self) -> &mut Vec<SynValue> {
        if !self.is_values() {
            let v = std::mem::replace(&mut self.0, Repr::Values(Vec::new()));
            self.0 = Repr::Values(boxed(v));
        }
        match &mut self.0 {
            Repr::Values(v) => v,
            _ => unreachable!("recién convertida"),
        }
    }

    /// Agrega `x` al final. Una lista vacía toma la forma del primer elemento; una lista sin caja
    /// sigue así mientras le lleguen números de su tipo (si no, pasa a valores).
    pub fn push(&mut self, x: SynValue) {
        match (&mut self.0, &x) {
            (Repr::Ints(v), SynValue::Number(Number::Int(n))) => v.push(*n),
            (Repr::Floats(v), SynValue::Number(Number::Float(f))) => v.push(*f),
            (Repr::Values(v), SynValue::Number(Number::Int(n))) if v.is_empty() => self.0 = Repr::Ints(vec![*n]),
            (Repr::Values(v), SynValue::Number(Number::Float(f))) if v.is_empty() => self.0 = Repr::Floats(vec![*f]),
            _ => self.values_mut().push(x),
        }
    }

    /// Cambia el elemento `i` (que existe) por `x`, sin pasar a valores si `x` es de su tipo.
    pub fn set(&mut self, i: usize, x: SynValue) {
        match (&mut self.0, &x) {
            (Repr::Ints(v), SynValue::Number(Number::Int(n))) => v[i] = *n,
            (Repr::Floats(v), SynValue::Number(Number::Float(f))) => v[i] = *f,
            _ => self.values_mut()[i] = x,
        }
    }

    /// Los elementos como valores (una copia).
    pub fn to_vec(&self) -> Vec<SynValue> {
        match &self.0 {
            Repr::Values(v) => v.clone(),
            r => boxed(r.clone()),
        }
    }

    /// Los elementos como valores (sin copiar si ya lo son).
    pub fn into_vec(self) -> Vec<SynValue> {
        match self.0 {
            Repr::Values(v) => v,
            r => boxed(r),
        }
    }

    /// Recorre los elementos sin pasar la lista a valores.
    pub fn for_each(&self, mut f: impl FnMut(&SynValue)) {
        match &self.0 {
            Repr::Values(v) => v.iter().for_each(f),
            Repr::Ints(v) => v.iter().for_each(|x| f(&SynValue::Number(Number::Int(*x)))),
            Repr::Floats(v) => v.iter().for_each(|x| f(&SynValue::Number(Number::Float(*x)))),
        }
    }

    /// Los elementos por valor (copias), sin pasar la lista a valores.
    pub fn iter_owned(&self) -> impl Iterator<Item = SynValue> + '_ {
        (0..self.len()).map(move |i| self.get(i).expect("dentro del largo"))
    }
}

/// Los números sin caja como valores.
fn boxed(r: Repr) -> Vec<SynValue> {
    match r {
        Repr::Values(v) => v,
        Repr::Ints(v) => v.into_iter().map(|x| SynValue::Number(Number::Int(x))).collect(),
        Repr::Floats(v) => v.into_iter().map(|x| SynValue::Number(Number::Float(x))).collect(),
    }
}

/// Los elementos de `l` como valores, para leerlos: una lista sin caja pasa a valores (para siempre).
/// No hay que tenerla prestada (`borrow`) mientras tanto si no es de valores: se cambia.
///
/// Una lista CONGELADA (R2, `frozen.rs`) no se cambia nunca —la leen otros hilos—: si es sin caja, se
/// devuelve una copia en valores y la lista sigue en 8 B por elemento. Leer nunca escribe un objeto
/// congelado (hasta la auditoría de R2, esto entraba en pánico: `count(IDS)` con `IDS` un `range`
/// global leído desde `serve` o `parallel_map`).
pub fn list_values(l: &ListRef) -> ListRead<'_> {
    let b = l.borrow();
    if b.is_values() {
        return ListRead::Values(Ref::map(b, |s| s.as_values().expect("de valores").as_slice()));
    }
    if ListRef::is_frozen(l) {
        return ListRead::Copy(b.to_vec());
    }
    drop(b);
    l.borrow_mut().values_mut();
    ListRead::Values(Ref::map(l.borrow(), |s| s.as_values().expect("de valores").as_slice()))
}

/// Los elementos de `l` como valores para LEER sin cambiar su forma: los de una lista de valores,
/// prestados; los de una sin caja, una copia (para lo que ya recorre la lista entera: mostrarla,
/// compararla). Lo que lee por índice en un bucle usa `SynList::get`/`elem`, no esto.
pub fn list_read(l: &ListRef) -> ListRead<'_> {
    let b = l.borrow();
    if b.is_values() {
        ListRead::Values(Ref::map(b, |s| s.as_values().expect("de valores").as_slice()))
    } else {
        let v = b.to_vec();
        ListRead::Copy(v)
    }
}

/// Los elementos `[start, end)` de `l` para LEER (una página): prestados si es de valores; si es
/// sin caja, una copia de ese tramo solo. No toca el resto de la lista ni cambia su forma. Los
/// bordes se recortan al largo.
pub fn list_read_range(l: &ListRef, start: usize, end: usize) -> ListRead<'_> {
    let b = l.borrow();
    let end = end.min(b.len());
    let start = start.min(end);
    if b.is_values() {
        ListRead::Values(Ref::map(b, |s| &s.as_values().expect("de valores")[start..end]))
    } else {
        ListRead::Copy((start..end).filter_map(|i| b.get(i)).collect())
    }
}

/// Ver `list_read`.
pub enum ListRead<'a> {
    Values(Ref<'a, [SynValue]>),
    Copy(Vec<SynValue>),
}

impl std::ops::Deref for ListRead<'_> {
    type Target = [SynValue];
    fn deref(&self) -> &[SynValue] {
        match self {
            ListRead::Values(r) => r,
            ListRead::Copy(v) => v,
        }
    }
}

/// Los elementos de `l` como valores, para cambiarlos (ver `list_values`).
pub fn list_values_mut(l: &ListRef) -> RefMut<'_, Vec<SynValue>> {
    RefMut::map(l.borrow_mut(), |s| s.values_mut())
}

impl From<Vec<SynValue>> for SynList {
    fn from(v: Vec<SynValue>) -> SynList {
        SynList(Repr::Values(v))
    }
}

impl FromIterator<SynValue> for SynList {
    fn from_iter<I: IntoIterator<Item = SynValue>>(it: I) -> SynList {
        SynList(Repr::Values(it.into_iter().collect()))
    }
}

impl fmt::Debug for SynList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter_owned()).finish()
    }
}

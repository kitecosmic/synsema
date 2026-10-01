//! El cuerpo de una lista (F4.8e de specs/compute-rendimiento.md): `ListRef` es
//! `Rc<RefCell<SynList>>`. Por ahora sólo valores, con la API de un `Vec<SynValue>` (paso 1: el tipo
//! propio sin cambiar nada); el paso 2 suma enteros y floats sin caja detrás de esta misma API.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::types::SynValue;

/// Los elementos de una lista.
#[derive(Clone, Default)]
pub struct SynList(Vec<SynValue>);

impl SynList {
    pub fn new() -> SynList {
        SynList(Vec::new())
    }

    pub fn with_capacity(n: usize) -> SynList {
        SynList(Vec::with_capacity(n))
    }

    /// Los elementos, como `Vec` (sin copiar).
    pub fn into_vec(self) -> Vec<SynValue> {
        self.0
    }
}

impl Deref for SynList {
    type Target = Vec<SynValue>;
    fn deref(&self) -> &Vec<SynValue> {
        &self.0
    }
}

impl DerefMut for SynList {
    fn deref_mut(&mut self) -> &mut Vec<SynValue> {
        &mut self.0
    }
}

impl From<Vec<SynValue>> for SynList {
    fn from(v: Vec<SynValue>) -> SynList {
        SynList(v)
    }
}

impl FromIterator<SynValue> for SynList {
    fn from_iter<I: IntoIterator<Item = SynValue>>(it: I) -> SynList {
        SynList(it.into_iter().collect())
    }
}

impl IntoIterator for SynList {
    type Item = SynValue;
    type IntoIter = std::vec::IntoIter<SynValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a SynList {
    type Item = &'a SynValue;
    type IntoIter = std::slice::Iter<'a, SynValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Debug for SynList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

//! El mapa de Synsema (F4.4 de specs/compute-rendimiento.md): claves compartidas y un hasher por
//! proceso.
//!
//! - [`Key`]: la clave, un `Rc<str>` compartido. Un literal del chunk, el nombre de un `set m.k`,
//!   el texto de un `set m[k]`, las columnas de un CSV o las claves repetidas de un JSON se guardan
//!   una vez y cada mapa suma una referencia (como los strings internados de CPython/V8/Lua), en vez
//!   de copiar el texto en cada registro. Hashea y compara igual que `str` (`Borrow<str>`), así que
//!   `get("x")` sigue andando. Es opaca: F4.5 puede cambiar cómo se guarda sin tocar a los llamadores.
//! - [`SynMap`]: el orden de inserción de siempre (`IndexMap`) detrás de una API propia, la que usan
//!   los llamadores (el truco de `Bindings`, F1.5): F4.5 cambia la representación (formas, modo
//!   diccionario) sin tocarlos.
//! - [`KeyHasher`]: SipHash-1-3 (el de `std`) con una semilla aleatoria **por proceso**, como
//!   CPython, Swift o V8 (por isolate): la misma defensa contra colisiones elegidas, sin los 16 bytes
//!   de semilla que `RandomState` guarda en cada mapa. El orden de iteración no depende del hash.

use std::borrow::Borrow;
use std::collections::hash_map::{DefaultHasher, RandomState};
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;
use std::sync::OnceLock;

use indexmap::IndexMap;

use crate::types::SynValue;

/// La clave de un mapa: texto compartido (`Rc<str>`). Ver el módulo.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key(Rc<str>);

impl Key {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// La clave de un valor (`m[k]`, un literal `{k: …}`): un texto comparte su `Rc` (sin copiar);
    /// cualquier otro valor, su texto (`{1: "a"}` → la clave `"1"`, como siempre).
    #[inline]
    pub fn of_value(v: &SynValue) -> Key {
        match v {
            SynValue::Text(s) => Key(s.clone()),
            other => Key::from(other.to_string()),
        }
    }
    /// El texto compartido: armar un `SynValue::Text` con él no copia (`keys(m)`).
    #[inline]
    pub fn rc(&self) -> &Rc<str> {
        &self.0
    }
}

impl Hash for Key {
    #[inline]
    fn hash<H: Hasher>(&self, h: &mut H) {
        // Igual que `str` (y `String`): lo exige `Borrow<str>` para buscar con `&str`.
        (*self.0).hash(h)
    }
}

impl Deref for Key {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Key {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Key {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl From<&str> for Key {
    #[inline]
    fn from(s: &str) -> Key {
        Key(Rc::from(s))
    }
}

impl From<String> for Key {
    #[inline]
    fn from(s: String) -> Key {
        Key(Rc::from(s))
    }
}

impl From<&String> for Key {
    #[inline]
    fn from(s: &String) -> Key {
        Key(Rc::from(s.as_str()))
    }
}

impl From<Rc<str>> for Key {
    #[inline]
    fn from(s: Rc<str>) -> Key {
        Key(s)
    }
}

impl From<&Rc<str>> for Key {
    #[inline]
    fn from(s: &Rc<str>) -> Key {
        Key(s.clone())
    }
}

impl From<&Key> for Key {
    #[inline]
    fn from(k: &Key) -> Key {
        k.clone()
    }
}

impl From<Key> for String {
    #[inline]
    fn from(k: Key) -> String {
        k.0.to_string()
    }
}

impl PartialEq<str> for Key {
    #[inline]
    fn eq(&self, o: &str) -> bool {
        &*self.0 == o
    }
}

impl PartialEq<&str> for Key {
    #[inline]
    fn eq(&self, o: &&str) -> bool {
        &*self.0 == *o
    }
}

impl PartialEq<String> for Key {
    #[inline]
    fn eq(&self, o: &String) -> bool {
        &*self.0 == o.as_str()
    }
}

impl PartialEq<Key> for str {
    #[inline]
    fn eq(&self, o: &Key) -> bool {
        self == &*o.0
    }
}

impl PartialEq<Key> for &str {
    #[inline]
    fn eq(&self, o: &Key) -> bool {
        *self == &*o.0
    }
}

impl PartialEq<Key> for String {
    #[inline]
    fn eq(&self, o: &Key) -> bool {
        self.as_str() == &*o.0
    }
}

/// SipHash-1-3 con una semilla por proceso (ver el módulo). Tamaño cero.
#[derive(Clone, Copy, Default)]
pub struct KeyHasher;

impl BuildHasher for KeyHasher {
    type Hasher = DefaultHasher;
    #[inline]
    fn build_hasher(&self) -> DefaultHasher {
        static SEED: OnceLock<RandomState> = OnceLock::new();
        SEED.get_or_init(RandomState::new).build_hasher()
    }
}

type Inner = IndexMap<Key, SynValue, KeyHasher>;

/// El mapa de Synsema: orden de inserción, claves [`Key`]. Ver el módulo.
#[derive(Clone, Default)]
pub struct SynMap(Inner);

impl SynMap {
    #[inline]
    pub fn new() -> SynMap {
        SynMap(IndexMap::with_hasher(KeyHasher))
    }
    #[inline]
    pub fn with_capacity(n: usize) -> SynMap {
        SynMap(IndexMap::with_capacity_and_hasher(n, KeyHasher))
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[inline]
    pub fn get(&self, k: &str) -> Option<&SynValue> {
        self.0.get(k)
    }
    #[inline]
    pub fn get_mut(&mut self, k: &str) -> Option<&mut SynValue> {
        self.0.get_mut(k)
    }
    #[inline]
    pub fn get_key_value(&self, k: &str) -> Option<(&Key, &SynValue)> {
        self.0.get_key_value(k)
    }
    #[inline]
    pub fn contains_key(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    /// Inserta o reemplaza (la clave vieja y su posición se quedan, como `IndexMap`).
    #[inline]
    pub fn insert(&mut self, k: impl Into<Key>, v: SynValue) -> Option<SynValue> {
        self.0.insert(k.into(), v)
    }
    /// `set m.k to v`: si la clave ya está, sólo cambia el valor (no arma una clave nueva para
    /// tirarla); si no, la agrega al final. Mismo resultado que `insert`.
    #[inline]
    pub fn set(&mut self, k: &str, v: SynValue) -> Option<SynValue> {
        if let Some(slot) = self.0.get_mut(k) {
            return Some(std::mem::replace(slot, v));
        }
        self.0.insert(Key::from(k), v);
        None
    }
    /// `set m[k] to v`: como [`SynMap::set`]; si la clave es un texto nuevo, la comparte.
    #[inline]
    pub fn set_value_key(&mut self, k: &SynValue, v: SynValue) -> Option<SynValue> {
        match k {
            SynValue::Text(s) => {
                if let Some(slot) = self.0.get_mut(&**s) {
                    return Some(std::mem::replace(slot, v));
                }
                self.0.insert(Key(s.clone()), v);
                None
            }
            other => self.set(&other.to_string(), v),
        }
    }
    #[inline]
    pub fn insert_full(&mut self, k: impl Into<Key>, v: SynValue) -> (usize, Option<SynValue>) {
        self.0.insert_full(k.into(), v)
    }
    #[inline]
    pub fn shift_remove(&mut self, k: &str) -> Option<SynValue> {
        self.0.shift_remove(k)
    }
    #[inline]
    pub fn shift_remove_entry(&mut self, k: &str) -> Option<(Key, SynValue)> {
        self.0.shift_remove_entry(k)
    }
    #[inline]
    pub fn swap_remove(&mut self, k: &str) -> Option<SynValue> {
        self.0.swap_remove(k)
    }
    #[inline]
    pub fn shift_remove_index(&mut self, i: usize) -> Option<(Key, SynValue)> {
        self.0.shift_remove_index(i)
    }
    #[inline]
    pub fn get_index(&self, i: usize) -> Option<(&Key, &SynValue)> {
        self.0.get_index(i)
    }
    #[inline]
    pub fn get_index_mut(&mut self, i: usize) -> Option<(&Key, &mut SynValue)> {
        self.0.get_index_mut(i)
    }
    #[inline]
    pub fn get_full(&self, k: &str) -> Option<(usize, &Key, &SynValue)> {
        self.0.get_full(k)
    }
    #[inline]
    pub fn get_index_of(&self, k: &str) -> Option<usize> {
        self.0.get_index_of(k)
    }
    #[inline]
    pub fn first(&self) -> Option<(&Key, &SynValue)> {
        self.0.first()
    }
    #[inline]
    pub fn last(&self) -> Option<(&Key, &SynValue)> {
        self.0.last()
    }
    #[inline]
    pub fn iter(&self) -> indexmap::map::Iter<'_, Key, SynValue> {
        self.0.iter()
    }
    #[inline]
    pub fn iter_mut(&mut self) -> indexmap::map::IterMut<'_, Key, SynValue> {
        self.0.iter_mut()
    }
    #[inline]
    pub fn keys(&self) -> indexmap::map::Keys<'_, Key, SynValue> {
        self.0.keys()
    }
    #[inline]
    pub fn values(&self) -> indexmap::map::Values<'_, Key, SynValue> {
        self.0.values()
    }
    #[inline]
    pub fn values_mut(&mut self) -> indexmap::map::ValuesMut<'_, Key, SynValue> {
        self.0.values_mut()
    }
    #[inline]
    pub fn retain(&mut self, f: impl FnMut(&Key, &mut SynValue) -> bool) {
        self.0.retain(f)
    }
    #[inline]
    pub fn clear(&mut self) {
        self.0.clear()
    }
    #[inline]
    pub fn reserve(&mut self, n: usize) {
        self.0.reserve(n)
    }
    #[inline]
    pub fn sort_keys(&mut self) {
        self.0.sort_keys()
    }
    #[inline]
    pub fn sort_by(&mut self, f: impl FnMut(&Key, &SynValue, &Key, &SynValue) -> std::cmp::Ordering) {
        self.0.sort_by(f)
    }
}

impl fmt::Debug for SynMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Igual que el `Debug` de `IndexMap<String, _>`.
        f.debug_map().entries(self.0.iter().map(|(k, v)| (k.as_str(), v))).finish()
    }
}

impl std::ops::Index<&str> for SynMap {
    type Output = SynValue;
    /// Como `IndexMap`: entra en pánico si la clave no está (sólo donde el llamador ya lo sabe).
    fn index(&self, k: &str) -> &SynValue {
        &self.0[k]
    }
}

impl<K: Into<Key>> Extend<(K, SynValue)> for SynMap {
    fn extend<I: IntoIterator<Item = (K, SynValue)>>(&mut self, it: I) {
        self.0.extend(it.into_iter().map(|(k, v)| (k.into(), v)))
    }
}

impl<K: Into<Key>> FromIterator<(K, SynValue)> for SynMap {
    fn from_iter<I: IntoIterator<Item = (K, SynValue)>>(it: I) -> SynMap {
        let it = it.into_iter();
        let mut m = SynMap::with_capacity(it.size_hint().0);
        m.extend(it);
        m
    }
}

impl IntoIterator for SynMap {
    type Item = (Key, SynValue);
    type IntoIter = indexmap::map::IntoIter<Key, SynValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a SynMap {
    type Item = (&'a Key, &'a SynValue);
    type IntoIter = indexmap::map::Iter<'a, Key, SynValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut SynMap {
    type Item = (&'a Key, &'a mut SynValue);
    type IntoIter = indexmap::map::IterMut<'a, Key, SynValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::syn_int;

    fn int(v: &SynValue) -> i64 {
        match v {
            SynValue::Number(crate::number::Number::Int(i)) => *i,
            _ => panic!("no es un entero"),
        }
    }

    /// `SynMap` contra `IndexMap<String, i64>` (la representación de antes): la misma secuencia de
    /// operaciones da el mismo contenido en el mismo orden.
    #[test]
    fn same_as_indexmap_under_random_ops() {
        let mut seed: u64 = 0x5eed;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        for _round in 0..200 {
            let mut a = SynMap::new();
            let mut b: IndexMap<String, i64> = IndexMap::new();
            for step in 0..300 {
                let k = format!("k{}", next() % 24);
                match next() % 6 {
                    0 | 1 => {
                        let v = step as i64;
                        assert_eq!(a.insert(k.as_str(), syn_int(v)).map(|x| int(&x)), b.insert(k.clone(), v));
                    }
                    2 => assert_eq!(a.shift_remove(&k).map(|x| int(&x)), b.shift_remove(&k)),
                    3 => assert_eq!(a.swap_remove(&k).map(|x| int(&x)), b.swap_remove(&k)),
                    4 => assert_eq!(a.get_full(&k).map(|(i, k, v)| (i, k.to_string(), int(v))), b.get_full(&k).map(|(i, k, v)| (i, k.clone(), *v))),
                    _ => {
                        let i = if b.is_empty() { 0 } else { next() % b.len() };
                        assert_eq!(a.get_index(i).map(|(k, v)| (k.to_string(), int(v))), b.get_index(i).map(|(k, v)| (k.clone(), *v)));
                    }
                }
                assert_eq!(a.len(), b.len());
            }
            let got: Vec<(String, i64)> = a.iter().map(|(k, v)| (k.to_string(), int(v))).collect();
            let want: Vec<(String, i64)> = b.iter().map(|(k, v)| (k.clone(), *v)).collect();
            assert_eq!(got, want);
        }
    }

    /// `Borrow<str>` exige que la clave hashee como su texto: si no, `get("x")` no la encuentra.
    #[test]
    fn key_hashes_like_str() {
        let h = KeyHasher;
        for s in ["", "id", "valor", "a\"b", "é", "x\ny"] {
            assert_eq!(h.hash_one(Key::from(s)), h.hash_one(s));
            assert_eq!(h.hash_one(Key::from(s.to_string())), h.hash_one(s));
        }
        assert_eq!(std::mem::size_of::<KeyHasher>(), 0);
    }

    /// Un texto como clave comparte su `Rc` (no copia); otro valor usa su texto.
    #[test]
    fn of_value_shares_text() {
        let t: Rc<str> = Rc::from("clave");
        let k = Key::of_value(&SynValue::Text(t.clone()));
        assert!(Rc::ptr_eq(k.rc(), &t));
        assert_eq!(Key::of_value(&syn_int(7)).as_str(), "7");
    }
}

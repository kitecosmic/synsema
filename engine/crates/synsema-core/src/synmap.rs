//! El mapa de Synsema (F4.4 y F4.5 de specs/compute-rendimiento.md).
//!
//! - [`Key`]: la clave, un `Rc<str>` compartido. Un literal del chunk, el nombre de un `set m.k`,
//!   el texto de un `set m[k]`, las columnas de un CSV o las claves repetidas de un JSON se guardan
//!   una vez y cada mapa suma una referencia (como los strings internados de CPython/V8/Lua), en vez
//!   de copiar el texto en cada registro. Hashea y compara igual que `str` (`Borrow<str>`), así que
//!   `get("x")` sigue andando.
//! - [`MapObj`]: el cuerpo de un mapa, como los objetos de V8/JSC. Una **forma** compartida dice qué
//!   claves hay y en qué orden; los valores van **en línea**, en el mismo malloc que el cuerpo, con
//!   el tamaño exacto que tenía el mapa al armarse. Un registro `{"id", "valor"}` es un solo malloc
//!   de 80 bytes. Si el mapa crece más allá de sus lugares, los valores de más van afuera (el
//!   *backing store* de V8); con más de [`MAX_SHAPED`] claves, o cuando una forma tiene demasiadas
//!   hijas (claves que no se repiten), pasa a **modo diccionario**: la tabla hash de siempre.
//!   `MapRef = Rc<RefCell<MapObj>>`.
//! - [`SynMap`]: el mismo tipo sin lugares en línea (8 bytes, `new()` sin malloc), el mapa que arman
//!   los llamadores antes de volverlo un valor ([`SynMap::into_ref`]). Se usa como un `MapObj`
//!   (`Deref`): una sola implementación.
//! - [`KeyHasher`]: SipHash-1-3 (el de `std`) con una semilla aleatoria **por proceso**, como
//!   CPython, Swift o V8 (por isolate): la misma defensa contra colisiones elegidas, sin los 16 bytes
//!   de semilla que `RandomState` guarda en cada mapa.
//!
//! La semántica es la de `IndexMap` en todos los modos: orden de inserción, reemplazar deja la
//! clave en su lugar, `shift_remove` conserva el orden del resto, `swap_remove` mueve la última al
//! hueco, reinsertar agrega al final. El modo no se ve desde el lenguaje.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::hash_map::{DefaultHasher, RandomState};
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::rc::{Rc, Weak};
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

impl std::borrow::Borrow<str> for Key {
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

/// Con más claves que esto un mapa pasa a modo diccionario (la tabla hash).
pub const MAX_SHAPED: usize = 32;
/// Una forma con más hijas vivas que esto no suma transiciones: una clave nueva desde ella lleva
/// el mapa a modo diccionario (claves que no se repiten entre mapas, como `m[id]` con un id
/// distinto en cada uno: V8 corta igual).
const MAX_CHILDREN: usize = 64;
/// Desde cuántas claves la forma arma un índice por texto (uno, compartido por todos sus mapas);
/// con menos, buscar es recorrer las claves.
const INDEX_FROM: usize = 9;

type Dict = IndexMap<Key, SynValue, KeyHasher>;

/// Las claves de un mapa, en orden, compartidas por todos los mapas que las tienen (las *hidden
/// classes* de V8, las *structures* de JSC). Inmutable: agregar una clave es pasar a la forma hija.
struct Shape {
    /// La madre, con puntero fuerte (el *back pointer* de V8): la cadena vive mientras viva una
    /// hija. Sin esto, armar `{"id", "valor"}` recreaba la forma de `{"id"}` en cada registro.
    _parent: Option<Rc<Node>>,
    keys: Box<[Key]>,
    /// Las transiciones: la forma hija por cada clave agregada. `Weak`: una forma que ningún mapa
    /// usa se libera (y su entrada se poda).
    children: RefCell<Vec<(Key, Weak<Node>)>>,
    index: OnceCell<HashMap<Key, u32, KeyHasher>>,
}

impl Shape {
    #[inline]
    fn position(&self, k: &str) -> Option<usize> {
        if self.keys.len() < INDEX_FROM {
            self.keys.iter().position(|x| x.as_str() == k)
        } else {
            let ix = self
                .index
                .get_or_init(|| self.keys.iter().enumerate().map(|(i, k)| (k.clone(), i as u32)).collect());
            ix.get(k).map(|&i| i as usize)
        }
    }
}

/// Lo que dice cómo leer los valores de un cuerpo. Una forma se comparte; los otros dos son de un
/// solo mapa (una copia del mapa los copia).
enum Node {
    /// Todas las claves de la forma tienen su valor en línea.
    Shape(Shape),
    /// La forma y los valores que no entraron en línea (el *backing store* de V8): el valor `i` es
    /// `vals[i]` si hay lugar en línea, si no `extra[i - lugares]`.
    Grown { shape: Rc<Node>, extra: Vec<SynValue> },
    /// Modo diccionario: todo acá, los lugares en línea quedan vacíos.
    Dict(Dict),
}

#[inline]
fn shape_of(n: &Node) -> &Shape {
    match n {
        Node::Shape(s) => s,
        _ => unreachable!("no es una forma"),
    }
}

thread_local! {
    static ROOT: Rc<Node> = Rc::new(Node::Shape(Shape {
        _parent: None,
        keys: Box::new([]),
        children: RefCell::new(Vec::new()),
        index: OnceCell::new(),
    }));
}

fn root() -> Rc<Node> {
    ROOT.with(Rc::clone)
}

/// La forma de `parent` más la clave `k` al final: la transición guardada si la hay (por puntero
/// primero, por texto después), o una nueva. `None` si `parent` ya tiene demasiadas hijas.
fn transition(parent: &Rc<Node>, k: &Key) -> Option<Rc<Node>> {
    let s = shape_of(parent);
    let mut ch = s.children.borrow_mut();
    let mut dead = None;
    for (i, (ck, w)) in ch.iter().enumerate() {
        if Rc::ptr_eq(&ck.0, &k.0) || ck.as_str() == k.as_str() {
            match w.upgrade() {
                Some(n) => return Some(n),
                None => {
                    dead = Some(i);
                    break;
                }
            }
        }
    }
    if let Some(i) = dead {
        ch.swap_remove(i);
    }
    if ch.len() >= 16 && ch.len().is_power_of_two() {
        ch.retain(|(_, w)| w.strong_count() > 0);
    }
    // Una clave que ya está no hace una forma (armar un mapa con claves repetidas va por el camino
    // general, que reemplaza el valor en su lugar). Sólo al crear: una transición guardada nunca
    // repite claves.
    if ch.len() >= MAX_CHILDREN || s.position(k).is_some() {
        return None;
    }
    let mut keys = Vec::with_capacity(s.keys.len() + 1);
    keys.extend_from_slice(&s.keys);
    keys.push(k.clone());
    let n = Rc::new(Node::Shape(Shape {
        _parent: Some(parent.clone()),
        keys: keys.into_boxed_slice(),
        children: RefCell::new(Vec::new()),
        index: OnceCell::new(),
    }));
    ch.push((k.clone(), Rc::downgrade(&n)));
    Some(n)
}

/// Una copia propia de lo que es de un solo mapa (la forma se comparte).
fn clone_layout(n: &Rc<Node>) -> Rc<Node> {
    match &**n {
        Node::Shape(_) => n.clone(),
        Node::Grown { shape, extra } => Rc::new(Node::Grown { shape: shape.clone(), extra: extra.clone() }),
        Node::Dict(d) => Rc::new(Node::Dict(d.clone())),
    }
}

/// Para escribir en lo que es de un solo mapa (`Grown`/`Dict`). Siempre es único (una copia del
/// mapa lo copia); si no lo fuera, se copia antes de escribir.
fn own(n: &mut Rc<Node>) -> &mut Node {
    if Rc::get_mut(n).is_none() {
        assert!(!matches!(**n, Node::Shape(_)), "una forma compartida no se escribe");
        *n = clone_layout(n);
    }
    Rc::get_mut(n).expect("recién copiado")
}

/// El cuerpo de un mapa: cómo leerlo y los valores en línea. `S` es `[SynValue]` en un mapa que es
/// un valor ([`MapObj`]) y `[SynValue; 0]` en uno que se está armando ([`SynMap`]).
pub struct MapBody<S: ?Sized> {
    /// `None`: vacío.
    layout: Option<Rc<Node>>,
    vals: S,
}

/// El mapa de un valor de Synsema (ver el módulo).
pub type MapObj = MapBody<[SynValue]>;
/// Un mapa que se está armando: sin lugares en línea (ver el módulo).
pub type SynMap = MapBody<[SynValue; 0]>;
/// Un mapa como valor: un malloc con el cuerpo y sus valores en línea.
pub type MapRef = Rc<RefCell<MapObj>>;

// El que se arma: un puntero, a lo sumo 8 bytes (en wasm32 el puntero es de 4, pero la alineación
// de `SynValue` lo lleva a 8). El valor: un puntero gordo (puntero + largo).
const _: () = assert!(std::mem::size_of::<SynMap>() <= 8);
const _: () = assert!(std::mem::size_of::<MapRef>() == 2 * std::mem::size_of::<usize>());

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Empty,
    Shape,
    Grown,
    Dict,
}

macro_rules! new_body {
    ($layout:ident, $it:ident, $n:expr; $($k:literal)*) => {
        match $n {
            $($k => Rc::new(RefCell::new(MapBody {
                layout: $layout,
                vals: std::array::from_fn::<SynValue, $k, _>(|_| $it.next().unwrap_or(SynValue::Nothing)),
            })) as MapRef,)*
            _ => unreachable!("más de MAX_SHAPED lugares en línea"),
        }
    };
}

/// Un cuerpo con `n` lugares en línea (el malloc del mapa), llenos con `vals`.
fn new_body(layout: Option<Rc<Node>>, mut vals: impl Iterator<Item = SynValue>, n: usize) -> MapRef {
    new_body!(layout, vals, n; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32)
}

/// Una forma armada una vez para muchos mapas con las mismas claves en el mismo orden (las
/// columnas de un CSV, las claves de un literal): cada mapa es un malloc con sus valores en línea.
#[derive(Clone)]
pub struct ShapeRef(Rc<Node>);

impl ShapeRef {
    /// La forma de las `n` claves de `key_at` en orden. `None` si alguna se repite, si son más de
    /// [`MAX_SHAPED`] o si alguna transición es megamórfica: el llamador arma el mapa por el
    /// camino general (el mismo resultado).
    #[inline]
    pub fn of_keys(n: usize, mut key_at: impl FnMut(usize) -> Key) -> Option<ShapeRef> {
        if n > MAX_SHAPED {
            return None;
        }
        let mut s = root();
        for i in 0..n {
            s = transition(&s, &key_at(i))?;
        }
        Some(ShapeRef(s))
    }
    #[inline]
    pub fn len(&self) -> usize {
        shape_of(&self.0).keys.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Un mapa con esta forma y `vals` en orden (tiene que dar [`ShapeRef::len`] valores).
    #[inline]
    pub fn build(&self, vals: impl Iterator<Item = SynValue>) -> MapRef {
        let n = self.len();
        new_body(if n == 0 { None } else { Some(self.0.clone()) }, vals, n)
    }
}

/// El mapa de un literal: `slots` son clave, valor, clave, valor… (los registros de `MakeMap`); se
/// los lleva (quedan en `Nothing`). Con forma si se puede (un malloc); si no, el camino general.
pub fn map_from_pair_slots(slots: &mut [SynValue]) -> MapRef {
    let n = slots.len() / 2;
    let m = match ShapeRef::of_keys(n, |i| Key::of_value(&slots[2 * i])) {
        Some(s) => s.build((0..n).map(|i| std::mem::replace(&mut slots[2 * i + 1], SynValue::Nothing))),
        None => {
            // Con claves repetidas pueden quedar pocas: la capacidad no decide el modo.
            let mut m = SynMap::with_capacity(n.min(MAX_SHAPED));
            for i in 0..n {
                let v = std::mem::replace(&mut slots[2 * i + 1], SynValue::Nothing);
                m.insert(Key::of_value(&slots[2 * i]), v);
            }
            m.into_ref()
        }
    };
    for i in 0..n {
        slots[2 * i] = SynValue::Nothing;
    }
    m
}

/// Un mapa con los pares de `pairs` en orden (los saca: el búfer se reusa). Con forma si se puede
/// (un malloc); con claves repetidas gana el último valor en la posición de la primera, como
/// `insert`.
pub fn map_from_pairs(pairs: &mut Vec<(Key, SynValue)>) -> MapRef {
    match ShapeRef::of_keys(pairs.len(), |i| pairs[i].0.clone()) {
        Some(s) => s.build(pairs.drain(..).map(|(_, v)| v)),
        None => {
            let mut m = SynMap::with_capacity(pairs.len().min(MAX_SHAPED));
            m.extend(pairs.drain(..));
            m.into_ref()
        }
    }
}

impl SynMap {
    #[inline]
    pub fn new() -> SynMap {
        MapBody { layout: None, vals: [] }
    }
    /// Con lugar para `n` claves sin volver a pedir memoria.
    pub fn with_capacity(n: usize) -> SynMap {
        let layout = if n == 0 {
            None
        } else if n > MAX_SHAPED {
            Some(Rc::new(Node::Dict(Dict::with_capacity_and_hasher(n, KeyHasher))))
        } else {
            Some(Rc::new(Node::Grown { shape: root(), extra: Vec::with_capacity(n) }))
        };
        MapBody { layout, vals: [] }
    }
    /// El mapa como valor: un malloc con los valores en línea (la forma ya está armada).
    pub fn into_ref(mut self) -> MapRef {
        let Some(n) = self.layout.take() else {
            return new_body(None, std::iter::empty(), 0);
        };
        match Rc::try_unwrap(n) {
            Ok(Node::Grown { shape, extra }) => {
                if extra.is_empty() {
                    return new_body(None, std::iter::empty(), 0);
                }
                let len = extra.len();
                new_body(Some(shape), extra.into_iter(), len)
            }
            Ok(d @ Node::Dict(_)) => new_body(Some(Rc::new(d)), std::iter::empty(), 0),
            // Sin lugares en línea, una forma sola es la vacía.
            Ok(Node::Shape(_)) => new_body(None, std::iter::empty(), 0),
            // Lo de un solo mapa es único; si no lo fuera, se copia.
            Err(n) if matches!(*n, Node::Shape(_)) => new_body(None, std::iter::empty(), 0),
            Err(n) => SynMap { layout: Some(clone_layout(&n)), vals: [] }.into_ref(),
        }
    }
}

impl Default for SynMap {
    #[inline]
    fn default() -> SynMap {
        SynMap::new()
    }
}

impl Clone for SynMap {
    fn clone(&self) -> SynMap {
        MapBody { layout: self.layout.as_ref().map(clone_layout), vals: [] }
    }
}

impl Deref for SynMap {
    type Target = MapObj;
    #[inline]
    fn deref(&self) -> &MapObj {
        self
    }
}

impl DerefMut for SynMap {
    #[inline]
    fn deref_mut(&mut self) -> &mut MapObj {
        self
    }
}

impl MapObj {
    #[inline]
    fn kind(&self) -> Kind {
        match self.layout.as_deref() {
            None => Kind::Empty,
            Some(Node::Shape(_)) => Kind::Shape,
            Some(Node::Grown { .. }) => Kind::Grown,
            Some(Node::Dict(_)) => Kind::Dict,
        }
    }
    #[inline]
    pub fn len(&self) -> usize {
        match self.layout.as_deref() {
            None => 0,
            Some(Node::Shape(s)) => s.keys.len(),
            Some(Node::Grown { shape, .. }) => shape_of(shape).keys.len(),
            Some(Node::Dict(d)) => d.len(),
        }
    }
    /// Sin nodo es vacío (el caso común: un mapa recién armado, los `kwargs` de una llamada);
    /// un nodo vacío (una capacidad pedida, un diccionario que se vació) se cuenta.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.layout.is_none() || self.len() == 0
    }
    /// Una copia como valor (copy-on-write): mismos lugares en línea, la forma compartida.
    pub fn to_ref(&self) -> MapRef {
        new_body(self.layout.as_ref().map(clone_layout), self.vals.iter().cloned(), self.vals.len())
    }
    /// Una copia para seguir armando.
    pub fn to_map(&self) -> SynMap {
        let layout = match self.layout.as_deref() {
            None => None,
            Some(Node::Shape(s)) => {
                let shape = self.layout.clone().expect("forma");
                Some(Rc::new(Node::Grown { shape, extra: self.vals[..s.keys.len()].to_vec() }))
            }
            Some(Node::Grown { shape, extra }) => {
                let mut all = Vec::with_capacity(self.vals.len() + extra.len());
                all.extend(self.vals.iter().cloned());
                all.extend(extra.iter().cloned());
                Some(Rc::new(Node::Grown { shape: shape.clone(), extra: all }))
            }
            Some(Node::Dict(d)) => Some(Rc::new(Node::Dict(d.clone()))),
        };
        MapBody { layout, vals: [] }
    }
    /// Reemplaza todo el contenido por el de `m` (los lugares en línea se quedan).
    pub fn replace_with(&mut self, m: SynMap) {
        drop(self.take_pairs());
        self.rebuild(m.into_iter().collect());
    }
    /// Se lleva el contenido y deja el mapa vacío.
    pub fn take_map(&mut self) -> SynMap {
        let mut m = SynMap::new();
        m.rebuild(self.take_pairs());
        m
    }
    #[inline]
    pub fn get_index_of(&self, k: &str) -> Option<usize> {
        match self.layout.as_deref() {
            None => None,
            Some(Node::Shape(s)) => s.position(k),
            Some(Node::Grown { shape, .. }) => shape_of(shape).position(k),
            Some(Node::Dict(d)) => d.get_index_of(k),
        }
    }
    #[inline]
    pub fn get_index(&self, i: usize) -> Option<(&Key, &SynValue)> {
        match self.layout.as_deref() {
            None => None,
            Some(Node::Shape(s)) => Some((s.keys.get(i)?, &self.vals[i])),
            Some(Node::Grown { shape, extra }) => {
                let k = shape_of(shape).keys.get(i)?;
                let cap = self.vals.len();
                Some((k, if i < cap { &self.vals[i] } else { &extra[i - cap] }))
            }
            Some(Node::Dict(d)) => d.get_index(i),
        }
    }
    pub fn get_index_mut(&mut self, i: usize) -> Option<(&Key, &mut SynValue)> {
        if i >= self.len() {
            return None;
        }
        let cap = self.vals.len();
        match self.kind() {
            Kind::Empty => None,
            Kind::Shape => {
                let s = shape_of(self.layout.as_deref().expect("forma"));
                Some((&s.keys[i], &mut self.vals[i]))
            }
            Kind::Grown | Kind::Dict => match own(self.layout.as_mut().expect("nodo")) {
                Node::Grown { shape, extra } => {
                    let k = &shape_of(shape).keys[i];
                    Some((k, if i < cap { &mut self.vals[i] } else { &mut extra[i - cap] }))
                }
                Node::Dict(d) => d.get_index_mut(i).map(|(k, v)| (&*k, v)),
                Node::Shape(_) => unreachable!(),
            },
        }
    }
    #[inline]
    pub fn get_full(&self, k: &str) -> Option<(usize, &Key, &SynValue)> {
        if let Some(Node::Dict(d)) = self.layout.as_deref() {
            return d.get_full(k);
        }
        let i = self.get_index_of(k)?;
        let (k, v) = self.get_index(i)?;
        Some((i, k, v))
    }
    #[inline]
    pub fn get(&self, k: &str) -> Option<&SynValue> {
        self.get_full(k).map(|(_, _, v)| v)
    }
    #[inline]
    pub fn get_key_value(&self, k: &str) -> Option<(&Key, &SynValue)> {
        self.get_full(k).map(|(_, k, v)| (k, v))
    }
    #[inline]
    pub fn contains_key(&self, k: &str) -> bool {
        self.get_index_of(k).is_some()
    }
    #[inline]
    pub fn get_mut(&mut self, k: &str) -> Option<&mut SynValue> {
        if self.kind() == Kind::Dict {
            return self.dict_mut()?.get_mut(k);
        }
        let i = self.get_index_of(k)?;
        self.get_index_mut(i).map(|(_, v)| v)
    }
    #[inline]
    pub fn first(&self) -> Option<(&Key, &SynValue)> {
        self.get_index(0)
    }
    #[inline]
    pub fn last(&self) -> Option<(&Key, &SynValue)> {
        self.get_index(self.len().checked_sub(1)?)
    }

    /// Inserta o reemplaza (la clave vieja y su posición se quedan, como `IndexMap`).
    #[inline]
    pub fn insert(&mut self, k: impl Into<Key>, v: SynValue) -> Option<SynValue> {
        self.insert_full(k, v).1
    }
    pub fn insert_full(&mut self, k: impl Into<Key>, v: SynValue) -> (usize, Option<SynValue>) {
        let k = k.into();
        if let Some(d) = self.dict_mut() {
            return d.insert_full(k, v);
        }
        if let Some(i) = self.get_index_of(&k) {
            let slot = self.get_index_mut(i).expect("posición").1;
            return (i, Some(std::mem::replace(slot, v)));
        }
        (self.push_new(k, v), None)
    }
    /// `set m.k to v`: si la clave ya está, sólo cambia el valor (no arma una clave nueva para
    /// tirarla); si no, la agrega al final. Mismo resultado que `insert`.
    #[inline]
    pub fn set(&mut self, k: &str, v: SynValue) -> Option<SynValue> {
        if let Some(d) = self.dict_mut() {
            if let Some(slot) = d.get_mut(k) {
                return Some(std::mem::replace(slot, v));
            }
            d.insert(Key::from(k), v);
            return None;
        }
        if let Some(i) = self.get_index_of(k) {
            let slot = self.get_index_mut(i).expect("posición").1;
            return Some(std::mem::replace(slot, v));
        }
        self.push_new(Key::from(k), v);
        None
    }
    /// `set m[k] to v`: como [`MapObj::set`]; si la clave es un texto nuevo, la comparte.
    #[inline]
    pub fn set_value_key(&mut self, k: &SynValue, v: SynValue) -> Option<SynValue> {
        match k {
            SynValue::Text(s) => {
                if let Some(d) = self.dict_mut() {
                    if let Some(slot) = d.get_mut(&**s) {
                        return Some(std::mem::replace(slot, v));
                    }
                    d.insert(Key(s.clone()), v);
                    return None;
                }
                if let Some(i) = self.get_index_of(s) {
                    let slot = self.get_index_mut(i).expect("posición").1;
                    return Some(std::mem::replace(slot, v));
                }
                self.push_new(Key(s.clone()), v);
                None
            }
            other => self.set(&other.to_string(), v),
        }
    }

    /// Agrega `k` (que no está) al final y devuelve su posición.
    fn push_new(&mut self, k: Key, v: SynValue) -> usize {
        let len = self.len();
        let kind = self.kind();
        if kind != Kind::Dict {
            if len < MAX_SHAPED {
                let base = match self.layout.as_deref() {
                    Some(Node::Grown { shape, .. }) => shape.clone(),
                    Some(_) => self.layout.clone().expect("forma"),
                    None => root(),
                };
                if let Some(next) = transition(&base, &k) {
                    let cap = self.vals.len();
                    if len < cap {
                        self.vals[len] = v;
                        self.layout = Some(next);
                    } else if kind == Kind::Grown {
                        if let Node::Grown { shape, extra } = own(self.layout.as_mut().expect("nodo")) {
                            *shape = next;
                            extra.push(v);
                        }
                    } else {
                        self.layout = Some(Rc::new(Node::Grown { shape: next, extra: vec![v] }));
                    }
                    return len;
                }
            }
            let pairs = self.take_pairs();
            let mut d = Dict::with_capacity_and_hasher(pairs.len() + 1, KeyHasher);
            d.extend(pairs);
            self.layout = Some(Rc::new(Node::Dict(d)));
        }
        if let Some(d) = self.dict_mut() {
            d.insert(k, v);
        }
        len
    }

    fn dict_mut(&mut self) -> Option<&mut Dict> {
        if self.kind() != Kind::Dict {
            return None;
        }
        match own(self.layout.as_mut()?) {
            Node::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// Saca todo en orden y deja el mapa vacío (`layout = None`, lugares en línea vacíos).
    fn take_pairs(&mut self) -> Vec<(Key, SynValue)> {
        let Some(n) = self.layout.take() else {
            return Vec::new();
        };
        let take = |v: &mut SynValue| std::mem::replace(v, SynValue::Nothing);
        if let Node::Shape(s) = &*n {
            let len = s.keys.len();
            return s.keys.iter().cloned().zip(self.vals[..len].iter_mut().map(take)).collect();
        }
        let node = match Rc::try_unwrap(n) {
            Ok(node) => node,
            Err(n) => Rc::try_unwrap(clone_layout(&n)).ok().expect("copia propia"),
        };
        match node {
            Node::Grown { shape, extra } => {
                shape_of(&shape).keys.iter().cloned().zip(self.vals.iter_mut().map(take).chain(extra)).collect()
            }
            Node::Dict(d) => d.into_iter().collect(),
            Node::Shape(_) => unreachable!(),
        }
    }

    /// Arma el mapa (vacío) con `pairs` (claves distintas, en orden): la forma por transiciones,
    /// los valores en línea mientras haya lugar y el resto afuera; con más de [`MAX_SHAPED`]
    /// claves, o sin transición posible, un diccionario.
    fn rebuild(&mut self, pairs: Vec<(Key, SynValue)>) {
        debug_assert!(self.layout.is_none());
        if pairs.is_empty() {
            return;
        }
        if pairs.len() <= MAX_SHAPED {
            let mut s = Some(root());
            for (k, _) in &pairs {
                s = s.and_then(|p| transition(&p, k));
            }
            if let Some(s) = s {
                let cap = self.vals.len();
                let len = pairs.len();
                let mut extra = Vec::with_capacity(len.saturating_sub(cap));
                for (i, (_, v)) in pairs.into_iter().enumerate() {
                    if i < cap {
                        self.vals[i] = v;
                    } else {
                        extra.push(v);
                    }
                }
                self.layout = Some(if len <= cap { s } else { Rc::new(Node::Grown { shape: s, extra }) });
                return;
            }
        }
        let mut d = Dict::with_capacity_and_hasher(pairs.len(), KeyHasher);
        d.extend(pairs);
        self.layout = Some(Rc::new(Node::Dict(d)));
    }

    pub fn shift_remove_full(&mut self, k: &str) -> Option<(usize, Key, SynValue)> {
        if let Some(d) = self.dict_mut() {
            return d.shift_remove_full(k);
        }
        let i = self.get_index_of(k)?;
        let mut pairs = self.take_pairs();
        let (k, v) = pairs.remove(i);
        self.rebuild(pairs);
        Some((i, k, v))
    }
    #[inline]
    pub fn shift_remove(&mut self, k: &str) -> Option<SynValue> {
        self.shift_remove_full(k).map(|(_, _, v)| v)
    }
    #[inline]
    pub fn shift_remove_entry(&mut self, k: &str) -> Option<(Key, SynValue)> {
        self.shift_remove_full(k).map(|(_, k, v)| (k, v))
    }
    pub fn swap_remove(&mut self, k: &str) -> Option<SynValue> {
        if let Some(d) = self.dict_mut() {
            return d.swap_remove(k);
        }
        let i = self.get_index_of(k)?;
        let mut pairs = self.take_pairs();
        let (_, v) = pairs.swap_remove(i);
        self.rebuild(pairs);
        Some(v)
    }
    pub fn shift_remove_index(&mut self, i: usize) -> Option<(Key, SynValue)> {
        if let Some(d) = self.dict_mut() {
            return d.shift_remove_index(i);
        }
        if i >= self.len() {
            return None;
        }
        let mut pairs = self.take_pairs();
        let kv = pairs.remove(i);
        self.rebuild(pairs);
        Some(kv)
    }
    pub fn retain(&mut self, mut f: impl FnMut(&Key, &mut SynValue) -> bool) {
        if let Some(d) = self.dict_mut() {
            return d.retain(f);
        }
        let mut pairs = self.take_pairs();
        pairs.retain_mut(|(k, v)| f(k, v));
        self.rebuild(pairs);
    }
    pub fn clear(&mut self) {
        drop(self.take_pairs());
    }
    pub fn reserve(&mut self, n: usize) {
        match self.kind() {
            Kind::Dict => {
                if let Some(d) = self.dict_mut() {
                    d.reserve(n)
                }
            }
            Kind::Grown => {
                if let Node::Grown { extra, .. } = own(self.layout.as_mut().expect("nodo")) {
                    extra.reserve(n)
                }
            }
            Kind::Empty | Kind::Shape => {}
        }
    }
    pub fn sort_keys(&mut self) {
        if let Some(d) = self.dict_mut() {
            return d.sort_keys();
        }
        let mut pairs = self.take_pairs();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        self.rebuild(pairs);
    }
    pub fn sort_by(&mut self, mut f: impl FnMut(&Key, &SynValue, &Key, &SynValue) -> std::cmp::Ordering) {
        if let Some(d) = self.dict_mut() {
            return d.sort_by(f);
        }
        let mut pairs = self.take_pairs();
        pairs.sort_by(|a, b| f(&a.0, &a.1, &b.0, &b.1));
        self.rebuild(pairs);
    }

    pub fn iter(&self) -> Iter<'_> {
        match self.layout.as_deref() {
            None => Iter::Shaped { keys: Default::default(), vals: self.vals[..0].iter().chain(std::slice::Iter::default()) },
            Some(Node::Shape(s)) => Iter::Shaped {
                keys: s.keys.iter(),
                vals: self.vals[..s.keys.len()].iter().chain(std::slice::Iter::default()),
            },
            Some(Node::Grown { shape, extra }) => {
                Iter::Shaped { keys: shape_of(shape).keys.iter(), vals: self.vals.iter().chain(extra.iter()) }
            }
            Some(Node::Dict(d)) => Iter::Dict(d.iter()),
        }
    }
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        match self.kind() {
            Kind::Empty => {
                IterMut::Shaped { keys: Default::default(), vals: self.vals[..0].iter_mut().chain(std::slice::IterMut::default()) }
            }
            Kind::Shape => {
                let s = shape_of(self.layout.as_deref().expect("forma"));
                let len = s.keys.len();
                IterMut::Shaped { keys: s.keys.iter(), vals: self.vals[..len].iter_mut().chain(std::slice::IterMut::default()) }
            }
            Kind::Grown | Kind::Dict => match own(self.layout.as_mut().expect("nodo")) {
                Node::Grown { shape, extra } => IterMut::Shaped {
                    keys: shape_of(shape).keys.iter(),
                    vals: self.vals.iter_mut().chain(extra.iter_mut()),
                },
                Node::Dict(d) => IterMut::Dict(d.iter_mut()),
                Node::Shape(_) => unreachable!(),
            },
        }
    }
    #[inline]
    pub fn keys(&self) -> Keys<'_> {
        Keys(self.iter())
    }
    #[inline]
    pub fn values(&self) -> Values<'_> {
        Values(self.iter())
    }
    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_> {
        ValuesMut(self.iter_mut())
    }
}

/// La caché de un sitio que lee una clave fija (`m.k`, `m["k"]`: `GetProp`/`GetIndex`), como las
/// *inline caches* de V8: la forma que vio y la posición de la clave en ella. Si el mapa tiene esa
/// forma, el valor está en ese lugar en línea: una comparación de punteros y una carga, sin mirar
/// la clave. La forma queda fijada (`pin`) mientras la caché la recuerde: su dirección no puede
/// pasar a ser la de otra. En modo diccionario recuerda la posición (la caché de F3.6).
#[derive(Default)]
pub struct MapIc {
    shape: Cell<usize>,
    slot: Cell<u32>,
    pin: Cell<Option<Rc<Node>>>,
}

#[inline(always)]
fn addr(n: &Rc<Node>) -> usize {
    Rc::as_ptr(n) as usize
}

impl MapObj {
    /// El valor de `key` usando (y actualizando) la caché del sitio. **La clave tiene que ser la
    /// misma en cada ejecución del sitio** (`m.k`): con la forma que recuerda la caché, la posición
    /// alcanza. Para una clave que cambia, [`MapObj::get_cached_key`].
    #[inline(always)]
    pub fn get_cached(&self, key: &str, ic: &MapIc) -> Option<&SynValue> {
        if let Some(l) = &self.layout {
            if addr(l) == ic.shape.get() {
                return self.vals.get(ic.slot.get() as usize);
            }
        }
        self.get_cached_slow(key, ic)
    }

    /// Como [`MapObj::get_cached`] para un sitio cuya clave puede cambiar (`m[k]`): con la forma que
    /// recuerda la caché, además mira que la clave en esa posición sea `key`.
    #[inline(always)]
    pub fn get_cached_key(&self, key: &str, ic: &MapIc) -> Option<&SynValue> {
        if let Some(l) = &self.layout {
            if addr(l) == ic.shape.get() {
                let i = ic.slot.get() as usize;
                if shape_of(l).keys[i].as_str() == key {
                    return Some(&self.vals[i]);
                }
            }
        }
        self.get_cached_slow(key, ic)
    }

    /// El lugar de `key` para escribirlo (`set m.k`, el camino de un `set`, F4.6a), con la caché
    /// del sitio como [`MapObj::get_cached`]: la clave tiene que ser la misma en cada ejecución.
    #[inline(always)]
    pub fn get_cached_mut(&mut self, key: &str, ic: &MapIc) -> Option<&mut SynValue> {
        if let Some(l) = &self.layout {
            if addr(l) == ic.shape.get() {
                return self.vals.get_mut(ic.slot.get() as usize);
            }
        }
        self.get_cached_mut_slow(key, ic)
    }

    /// Como [`MapObj::get_cached_mut`] para una clave que puede cambiar (`m[k]`).
    #[inline(always)]
    pub fn get_cached_key_mut(&mut self, key: &str, ic: &MapIc) -> Option<&mut SynValue> {
        if let Some(l) = &self.layout {
            if addr(l) == ic.shape.get() {
                let i = ic.slot.get() as usize;
                if shape_of(l).keys[i].as_str() == key {
                    return Some(&mut self.vals[i]);
                }
            }
        }
        self.get_cached_mut_slow(key, ic)
    }

    /// Llena la caché como la lectura y da el lugar por el camino de siempre (una forma: su
    /// posición en línea; lo demás, `get_mut`).
    #[inline(never)]
    fn get_cached_mut_slow(&mut self, key: &str, ic: &MapIc) -> Option<&mut SynValue> {
        self.get_cached_slow(key, ic)?;
        if matches!(self.layout.as_deref(), Some(Node::Shape(_))) {
            return self.vals.get_mut(ic.slot.get() as usize);
        }
        self.get_mut(key)
    }

    #[inline(never)]
    fn get_cached_slow(&self, key: &str, ic: &MapIc) -> Option<&SynValue> {
        let l = self.layout.as_ref()?;
        match &**l {
            Node::Shape(s) => {
                let i = s.position(key)?;
                ic.shape.set(addr(l));
                ic.slot.set(i as u32);
                drop(ic.pin.replace(Some(l.clone())));
                Some(&self.vals[i])
            }
            Node::Dict(d) => {
                let c = ic.slot.get() as usize;
                if let Some((k, v)) = d.get_index(c) {
                    if k.as_str() == key {
                        return Some(v);
                    }
                }
                let (i, _, v) = d.get_full(key)?;
                ic.slot.set(i as u32);
                Some(v)
            }
            Node::Grown { .. } => self.get(key),
        }
    }
}

/// `(&clave, &valor)` en orden.
#[derive(Clone)]
pub enum Iter<'a> {
    Shaped {
        keys: std::slice::Iter<'a, Key>,
        vals: std::iter::Chain<std::slice::Iter<'a, SynValue>, std::slice::Iter<'a, SynValue>>,
    },
    Dict(indexmap::map::Iter<'a, Key, SynValue>),
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a Key, &'a SynValue);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Iter::Shaped { keys, vals } => Some((keys.next()?, vals.next()?)),
            Iter::Dict(it) => it.next(),
        }
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Iter::Shaped { keys, .. } => keys.size_hint(),
            Iter::Dict(it) => it.size_hint(),
        }
    }
}

impl DoubleEndedIterator for Iter<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Iter::Shaped { keys, vals } => Some((keys.next_back()?, vals.next_back()?)),
            Iter::Dict(it) => it.next_back(),
        }
    }
}

impl ExactSizeIterator for Iter<'_> {}

/// `(&clave, &mut valor)` en orden.
pub enum IterMut<'a> {
    Shaped {
        keys: std::slice::Iter<'a, Key>,
        vals: std::iter::Chain<std::slice::IterMut<'a, SynValue>, std::slice::IterMut<'a, SynValue>>,
    },
    Dict(indexmap::map::IterMut<'a, Key, SynValue>),
}

impl<'a> Iterator for IterMut<'a> {
    type Item = (&'a Key, &'a mut SynValue);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            IterMut::Shaped { keys, vals } => Some((keys.next()?, vals.next()?)),
            IterMut::Dict(it) => it.next(),
        }
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            IterMut::Shaped { keys, .. } => keys.size_hint(),
            IterMut::Dict(it) => it.size_hint(),
        }
    }
}

impl DoubleEndedIterator for IterMut<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            IterMut::Shaped { keys, vals } => Some((keys.next_back()?, vals.next_back()?)),
            IterMut::Dict(it) => it.next_back(),
        }
    }
}

impl ExactSizeIterator for IterMut<'_> {}

macro_rules! projection {
    ($name:ident, $inner:ident, $item:ty, $pat:pat => $out:expr) => {
        pub struct $name<'a>($inner<'a>);
        impl<'a> Iterator for $name<'a> {
            type Item = $item;
            #[inline]
            fn next(&mut self) -> Option<$item> {
                self.0.next().map(|$pat| $out)
            }
            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }
        }
        impl DoubleEndedIterator for $name<'_> {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                self.0.next_back().map(|$pat| $out)
            }
        }
        impl ExactSizeIterator for $name<'_> {}
    };
}

projection!(Keys, Iter, &'a Key, (k, _) => k);
projection!(Values, Iter, &'a SynValue, (_, v) => v);
projection!(ValuesMut, IterMut, &'a mut SynValue, (_, v) => v);

impl Clone for Keys<'_> {
    fn clone(&self) -> Self {
        Keys(self.0.clone())
    }
}

impl Clone for Values<'_> {
    fn clone(&self) -> Self {
        Values(self.0.clone())
    }
}

/// Las entradas de un [`SynMap`], por valor y en orden.
pub enum IntoIter {
    Pairs(std::vec::IntoIter<(Key, SynValue)>),
    Dict(indexmap::map::IntoIter<Key, SynValue>),
}

impl Iterator for IntoIter {
    type Item = (Key, SynValue);
    #[inline]
    fn next(&mut self) -> Option<(Key, SynValue)> {
        match self {
            IntoIter::Pairs(it) => it.next(),
            IntoIter::Dict(it) => it.next(),
        }
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            IntoIter::Pairs(it) => it.size_hint(),
            IntoIter::Dict(it) => it.size_hint(),
        }
    }
}

impl DoubleEndedIterator for IntoIter {
    #[inline]
    fn next_back(&mut self) -> Option<(Key, SynValue)> {
        match self {
            IntoIter::Pairs(it) => it.next_back(),
            IntoIter::Dict(it) => it.next_back(),
        }
    }
}

impl ExactSizeIterator for IntoIter {}

impl IntoIterator for SynMap {
    type Item = (Key, SynValue);
    type IntoIter = IntoIter;
    fn into_iter(mut self) -> IntoIter {
        if self.kind() == Kind::Dict {
            if let Some(n) = self.layout.take() {
                return match Rc::try_unwrap(n) {
                    Ok(Node::Dict(d)) => IntoIter::Dict(d.into_iter()),
                    Ok(_) => unreachable!(),
                    Err(n) => match &*n {
                        Node::Dict(d) => IntoIter::Dict(d.clone().into_iter()),
                        _ => unreachable!(),
                    },
                };
            }
        }
        IntoIter::Pairs(self.take_pairs().into_iter())
    }
}

impl<'a> IntoIterator for &'a MapObj {
    type Item = (&'a Key, &'a SynValue);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut MapObj {
    type Item = (&'a Key, &'a mut SynValue);
    type IntoIter = IterMut<'a>;
    fn into_iter(self) -> IterMut<'a> {
        self.iter_mut()
    }
}

impl<'a> IntoIterator for &'a SynMap {
    type Item = (&'a Key, &'a SynValue);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut SynMap {
    type Item = (&'a Key, &'a mut SynValue);
    type IntoIter = IterMut<'a>;
    fn into_iter(self) -> IterMut<'a> {
        self.iter_mut()
    }
}

impl fmt::Debug for MapObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Igual que el `Debug` de `IndexMap<String, _>`.
        f.debug_map().entries(self.iter().map(|(k, v)| (k.as_str(), v))).finish()
    }
}

impl fmt::Debug for SynMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl std::ops::Index<&str> for MapObj {
    type Output = SynValue;
    /// Como `IndexMap`: entra en pánico si la clave no está (sólo donde el llamador ya lo sabe).
    fn index(&self, k: &str) -> &SynValue {
        self.get(k).expect("IndexMap: key not found")
    }
}

impl<K: Into<Key>> Extend<(K, SynValue)> for SynMap {
    fn extend<I: IntoIterator<Item = (K, SynValue)>>(&mut self, it: I) {
        for (k, v) in it {
            self.insert(k, v);
        }
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

    fn rng(mut seed: u64) -> impl FnMut() -> usize {
        move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        }
    }

    fn pairs(m: &MapObj) -> Vec<(String, i64)> {
        m.iter().map(|(k, v)| (k.to_string(), int(v))).collect()
    }

    fn want(b: &IndexMap<String, i64>) -> Vec<(String, i64)> {
        b.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Una operación al azar sobre `a` (el mapa de Synsema) y `b` (la referencia, `IndexMap`), con el
    /// mismo resultado. Las claves salen de `keys` distintas: pocas mantienen el mapa con forma,
    /// muchas cruzan [`MAX_SHAPED`] y lo pasan a diccionario.
    fn step(a: &mut MapObj, b: &mut IndexMap<String, i64>, next: &mut impl FnMut() -> usize, keys: usize, n: i64) {
        let k = format!("k{}", next() % keys);
        match next() % 14 {
            0..=2 => assert_eq!(a.insert(k.as_str(), syn_int(n)).map(|x| int(&x)), b.insert(k.clone(), n)),
            3 => assert_eq!(a.set(&k, syn_int(n)).map(|x| int(&x)), b.insert(k.clone(), n)),
            4 => {
                let t = SynValue::Text(Rc::from(k.as_str()));
                assert_eq!(a.set_value_key(&t, syn_int(n)).map(|x| int(&x)), b.insert(k.clone(), n))
            }
            5 => assert_eq!(a.shift_remove(&k).map(|x| int(&x)), b.shift_remove(&k)),
            6 => assert_eq!(a.swap_remove(&k).map(|x| int(&x)), b.swap_remove(&k)),
            7 => {
                let i = next() % (b.len() + 1);
                assert_eq!(
                    a.shift_remove_index(i).map(|(k, v)| (k.to_string(), int(&v))),
                    b.shift_remove_index(i)
                )
            }
            8 => assert_eq!(
                a.get_full(&k).map(|(i, k, v)| (i, k.to_string(), int(v))),
                b.get_full(&k).map(|(i, k, v)| (i, k.clone(), *v))
            ),
            9 => {
                let i = next() % (b.len() + 1);
                if let Some((_, v)) = a.get_index_mut(i) {
                    *v = syn_int(n);
                }
                if let Some((_, v)) = b.get_index_mut(i) {
                    *v = n;
                }
            }
            10 => {
                let r = next() % 3;
                a.retain(|_, v| int(v) % 3 != r as i64);
                b.retain(|_, v| *v % 3 != r as i64);
            }
            11 => {
                if next() % 4 == 0 {
                    a.sort_keys();
                    b.sort_keys();
                } else {
                    a.sort_by(|_, x, _, y| int(x).cmp(&int(y)));
                    b.sort_by(|_, x, _, y| x.cmp(y));
                }
            }
            12 => {
                for v in a.values_mut() {
                    *v = syn_int(int(v) + 1);
                }
                for v in b.values_mut() {
                    *v += 1;
                }
            }
            _ => {
                if next() % 16 == 0 {
                    a.clear();
                    b.clear();
                }
            }
        }
        assert_eq!(a.len(), b.len());
        assert_eq!(a.get_index_of(&k), b.get_index_of(&k));
        assert_eq!(a.first().map(|(k, _)| k.to_string()), b.first().map(|(k, _)| k.clone()));
        assert_eq!(a.last().map(|(k, _)| k.to_string()), b.last().map(|(k, _)| k.clone()));
    }

    /// `SynMap` contra `IndexMap<String, i64>` (la representación de antes): la misma secuencia de
    /// operaciones da el mismo contenido en el mismo orden, en los tres modos (forma, valores
    /// afuera, diccionario) y pasando de uno a otro.
    #[test]
    fn same_as_indexmap_under_random_ops() {
        let mut next = rng(0x5eed);
        for round in 0..300 {
            let keys = [4, 12, 24, 40, 80][round % 5];
            let mut a = SynMap::new();
            let mut b: IndexMap<String, i64> = IndexMap::new();
            for n in 0..300 {
                step(&mut a, &mut b, &mut next, keys, n);
            }
            assert_eq!(pairs(&a), want(&b));
            let back: Vec<(String, i64)> = a.iter().rev().map(|(k, v)| (k.to_string(), int(v))).collect();
            assert_eq!(back, b.iter().rev().map(|(k, v)| (k.clone(), *v)).collect::<Vec<_>>());
        }
    }

    /// Lo mismo sobre mapas que son valores (`MapRef`, con lugares en línea): congelar, copiar
    /// (copy-on-write), seguir escribiendo en la copia sin tocar el original, y volver a armar.
    #[test]
    fn values_with_inline_slots_behave_the_same() {
        let mut next = rng(0xf45);
        for round in 0..300 {
            let keys = [3, 8, 20, 36, 70][round % 5];
            let mut a = SynMap::new();
            let mut b: IndexMap<String, i64> = IndexMap::new();
            for n in 0..(next() % 40) as i64 {
                step(&mut a, &mut b, &mut next, keys, n);
            }
            let r = a.into_ref();
            assert_eq!(pairs(&r.borrow()), want(&b));
            let snap = want(&b);
            let copy = r.borrow().to_ref();
            let mut b2 = b.clone();
            for n in 0..200 {
                step(&mut copy.borrow_mut(), &mut b2, &mut next, keys, 1000 + n);
            }
            assert_eq!(pairs(&copy.borrow()), want(&b2));
            assert_eq!(pairs(&r.borrow()), snap, "la copia escribió en el original");
            let again = copy.borrow().to_map();
            assert_eq!(pairs(&again), want(&b2));
            let taken = copy.borrow_mut().take_map();
            assert!(copy.borrow().is_empty());
            copy.borrow_mut().replace_with(taken);
            assert_eq!(pairs(&copy.borrow()), want(&b2));
            let owned: Vec<(String, i64)> = again.into_iter().map(|(k, v)| (k.to_string(), int(&v))).collect();
            assert_eq!(owned, want(&b2));
        }
    }

    /// Los modos: un registro literal es una forma con sus valores en línea, compartida con los otros
    /// registros iguales; crecer lleva los valores afuera; pasar de [`MAX_SHAPED`] claves, a diccionario.
    #[test]
    fn modes_and_shared_shapes() {
        let rec = |i: i64| {
            let mut m = SynMap::new();
            m.insert("id", syn_int(i));
            m.insert("valor", syn_int(i * i));
            m.into_ref()
        };
        let (a, b) = (rec(1), rec(2));
        assert!(a.borrow().kind() == Kind::Shape && a.borrow().vals.len() == 2);
        let same = Rc::ptr_eq(a.borrow().layout.as_ref().unwrap(), b.borrow().layout.as_ref().unwrap());
        assert!(same, "dos registros iguales no comparten la forma");
        a.borrow_mut().insert("extra", syn_int(7));
        assert!(a.borrow().kind() == Kind::Grown);
        assert_eq!(pairs(&a.borrow()), vec![("id".into(), 1), ("valor".into(), 1), ("extra".into(), 7)]);
        a.borrow_mut().shift_remove("id");
        assert!(a.borrow().kind() == Kind::Shape, "al borrar vuelve a entrar en línea");
        let mut big = SynMap::new();
        for i in 0..=MAX_SHAPED {
            big.insert(format!("c{}", i), syn_int(i as i64));
        }
        assert!(big.kind() == Kind::Dict);
        big.shift_remove("c0");
        assert_eq!(big.get_index(0).map(|(k, _)| k.to_string()), Some("c1".into()));
    }

    /// Claves que no se repiten entre mapas: la forma raíz no junta hijas sin límite (van a
    /// diccionario) y las formas que nadie usa se liberan.
    #[test]
    fn unrepeated_keys_do_not_pile_up_shapes() {
        let mut kept = Vec::new();
        for i in 0..5000 {
            let mut m = SynMap::new();
            m.insert(format!("id{}", i), syn_int(i));
            kept.push(m.into_ref());
        }
        let n = ROOT.with(|r| shape_of(r).children.borrow().len());
        assert!(n <= MAX_CHILDREN, "la raíz juntó {} hijas", n);
        assert!(kept.iter().all(|m| m.borrow().len() == 1));
        let v: i64 = kept.iter().enumerate().map(|(i, m)| int(m.borrow().get(&format!("id{}", i)).unwrap())).sum();
        assert_eq!(v, (0..5000).sum::<i64>());
        drop(kept);
        let mut m = SynMap::new();
        m.insert("nueva", syn_int(1));
        let live = ROOT.with(|r| shape_of(r).children.borrow().iter().filter(|(_, w)| w.strong_count() > 0).count());
        assert!(live <= 2, "quedaron {} formas vivas", live);
    }

    /// El armado directo (`MakeMap`, JSON, CSV) da lo mismo que `insert` en orden: claves
    /// repetidas (el último valor en la posición de la primera), más de [`MAX_SHAPED`], claves que
    /// no son texto, vacío. Con forma, un solo malloc.
    #[test]
    fn direct_build_same_as_insert() {
        let mut next = rng(0xd1);
        for _ in 0..400 {
            let n = next() % 45;
            let keys = 1 + next() % 50;
            let ps: Vec<(SynValue, i64)> = (0..n)
                .map(|i| {
                    let k = if next() % 7 == 0 { syn_int((next() % keys) as i64) } else { SynValue::Text(Rc::from(format!("k{}", next() % keys))) };
                    (k, i as i64)
                })
                .collect();
            let mut b: IndexMap<String, i64> = IndexMap::new();
            for (k, v) in &ps {
                b.insert(k.to_string(), *v);
            }
            let mut slots: Vec<SynValue> = ps.iter().flat_map(|(k, v)| [k.clone(), syn_int(*v)]).collect();
            let m = map_from_pair_slots(&mut slots);
            assert_eq!(pairs(&m.borrow()), want(&b));
            assert!(slots.iter().all(|v| matches!(v, SynValue::Nothing)));
            let mut buf: Vec<(Key, SynValue)> = ps.iter().map(|(k, v)| (Key::of_value(k), syn_int(*v))).collect();
            let m2 = map_from_pairs(&mut buf);
            assert_eq!(pairs(&m2.borrow()), want(&b));
            assert!(buf.is_empty());
            // Con claves repetidas va por el camino general, que al congelar también da forma: sólo
            // más de MAX_SHAPED claves distintas es un diccionario. Con forma, sin lugares de más.
            for m in [&m, &m2] {
                let m = m.borrow();
                assert_eq!(m.kind() == Kind::Dict, b.len() > MAX_SHAPED, "n={} distintas={}", n, b.len());
                if m.kind() == Kind::Shape {
                    assert_eq!(m.vals.len(), b.len());
                }
            }
        }
    }

    /// La caché de un sitio: da lo mismo que `get` con formas que cambian, diccionarios, valores
    /// afuera, claves que cambian (`get_cached_key`) y formas que se liberan y se rehacen.
    #[test]
    fn inline_cache_matches_get() {
        let mut next = rng(0x1c);
        let fixed = MapIc::default();
        let moving = MapIc::default();
        for round in 0..3000 {
            let n = next() % 40;
            let mut m = SynMap::new();
            for i in 0..n {
                m.insert(format!("c{}", next() % 45), syn_int(i as i64));
            }
            let r = m.into_ref();
            if round % 5 == 0 {
                r.borrow_mut().insert("extra", syn_int(-1));
            }
            let m = r.borrow();
            let as_int = |v: Option<&SynValue>| v.map(int);
            assert_eq!(as_int(m.get_cached("c7", &fixed)), as_int(m.get("c7")));
            for _ in 0..4 {
                let k = format!("c{}", next() % 45);
                assert_eq!(as_int(m.get_cached_key(&k, &moving)), as_int(m.get(&k)), "{}", k);
            }
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

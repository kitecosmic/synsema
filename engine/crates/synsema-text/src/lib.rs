//! `SynText`: el texto de Synsema (F4.6b de specs/compute-rendimiento.md).
//!
//! Un valor de dos palabras (16 B en 64 bits, como `Rc<str>`) con tres cosas que `Rc<str>` no da:
//! - **En línea hasta 15 B** (7 en 32 bits): el texto vive dentro del valor, sin pedir memoria
//!   (Swift, las SSO de C++). Palabras, campos de CSV, claves y valores cortos de JSON.
//! - **Compartido con una cuenta NO atómica** (como `Rc`): clonar suma uno. Un texto no cruza
//!   hilos (el tipo no es `Send` ni `Sync`, por el puntero crudo).
//! - **Capacidad**: agregar a un texto con un solo dueño crece en el lugar (×2, `realloc`), como
//!   `String`; con más de un dueño copia (copy-on-write, como el `make_unique` de listas y mapas).
//!
//! Representación (`w` = dos `usize`, orden de bytes nativo):
//! - en el montón: una palabra es el puntero a `Header` (cuenta y capacidad, seguido de los
//!   bytes) y la otra el largo, siempre < 2^(bits−1): el byte más alto del largo nunca tiene el
//!   bit alto. La palabra del largo es la que pone ese byte en un EXTREMO del valor: `w[1]` en
//!   little-endian (el último byte), `w[0]` en big-endian (el primero).
//! - en línea: ese byte extremo es la marca, `0x80 | largo`, y el texto ocupa los demás, seguidos
//!   (desde el byte 0 en little-endian, desde el 1 en big-endian). Miri encontró el error de la
//!   primera versión: con el largo siempre en `w[1]`, en big-endian la marca caía en el medio.
//!
//! Todo el `unsafe` del texto vive en este archivo (ver `engine/crates/synsema-core/tests/
//! unsafe_allowlist.rs`). Invariantes: los bytes `[0, len)` son UTF-8 válido siempre (se escriben
//! sólo desde `&str`); en el montón `len <= cap` y la cuenta es ≥ 1 mientras haya un valor.

#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{self, Layout};
use std::borrow::Borrow;
use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::ptr::NonNull;

const WORD: usize = std::mem::size_of::<usize>();
/// Cuántos bytes entran en línea: todo el valor menos el byte de la marca.
pub const INLINE_MAX: usize = 2 * WORD - 1;
/// El byte de la marca, dónde empieza el texto en línea y qué palabra es el largo (ver el módulo).
#[cfg(target_endian = "little")]
const TAG_BYTE: usize = 2 * WORD - 1;
#[cfg(target_endian = "little")]
const DATA: usize = 0;
#[cfg(target_endian = "little")]
const LEN_W: usize = 1;
#[cfg(target_endian = "big")]
const TAG_BYTE: usize = 0;
#[cfg(target_endian = "big")]
const DATA: usize = 1;
#[cfg(target_endian = "big")]
const LEN_W: usize = 0;
const PTR_W: usize = 1 - LEN_W;
const INLINE_BIT: u8 = 0x80;
/// La cuenta de un texto inmortal (ver `make_immortal`).
const IMMORTAL: usize = usize::MAX;
/// La cuenta de un texto inmortal CON ALCANCE (`make_immortal_logged`): se descongela al terminar,
/// así que no pasa a una región permanente (`is_scoped`). Todo lo ≥ esto es inmortal.
const SCOPED: usize = usize::MAX - 1;

#[repr(C)]
struct Header {
    strong: Cell<usize>,
    cap: usize,
}

const HDR: usize = std::mem::size_of::<Header>();

/// El texto. Ver el módulo.
#[repr(C)]
pub struct SynText {
    w: [usize; 2],
    /// Ni `Send` ni `Sync` (la cuenta no es atómica).
    _not_send: std::marker::PhantomData<*const u8>,
}

impl SynText {
    #[inline]
    fn bytes(&self) -> &[u8; 2 * WORD] {
        // SAFETY: `[usize; 2]` y `[u8; 2 * WORD]` tienen el mismo tamaño; la alineación de u8 es 1.
        unsafe { &*(self.w.as_ptr() as *const [u8; 2 * WORD]) }
    }
    #[inline]
    fn bytes_mut(&mut self) -> &mut [u8; 2 * WORD] {
        // SAFETY: ídem.
        unsafe { &mut *(self.w.as_mut_ptr() as *mut [u8; 2 * WORD]) }
    }
    /// Si el texto vive dentro del valor (hasta `INLINE_MAX` bytes: sin memoria aparte).
    #[inline]
    pub fn is_inline(&self) -> bool {
        self.bytes()[TAG_BYTE] & INLINE_BIT != 0
    }
    #[inline]
    fn header(&self) -> &Header {
        debug_assert!(!self.is_inline());
        // SAFETY: en el montón `w[PTR_W]` apunta a un `Header` vivo (la cuenta de este valor lo sostiene).
        unsafe { &*(self.w[PTR_W] as *const Header) }
    }
    #[inline]
    fn heap_ptr(&self) -> *mut u8 {
        // SAFETY: los bytes van justo después del header, dentro de la misma asignación.
        unsafe { (self.w[PTR_W] as *mut u8).add(HDR) }
    }
    fn layout(cap: usize) -> Layout {
        Layout::from_size_align(HDR.checked_add(cap).expect("texto demasiado largo"), std::mem::align_of::<Header>())
            .expect("texto demasiado largo")
    }

    /// El texto vacío (en línea).
    #[inline]
    pub const fn new() -> SynText {
        let mut b = [0u8; 2 * WORD];
        b[TAG_BYTE] = INLINE_BIT;
        // SAFETY: mismos tamaños; cualquier patrón de bits es un `[usize; 2]` válido.
        let w = unsafe { std::mem::transmute::<[u8; 2 * WORD], [usize; 2]>(b) };
        SynText { w, _not_send: std::marker::PhantomData }
    }

    fn inline_from(s: &str) -> SynText {
        debug_assert!(s.len() <= INLINE_MAX);
        let mut t = SynText::new();
        let b = t.bytes_mut();
        b[DATA..DATA + s.len()].copy_from_slice(s.as_bytes());
        b[TAG_BYTE] = INLINE_BIT | s.len() as u8;
        t
    }

    /// Un texto en el montón con `cap` bytes de lugar (≥ `s.len()`).
    fn heap_from(s: &str, cap: usize) -> SynText {
        let cap = cap.max(s.len());
        let layout = Self::layout(cap);
        // SAFETY: el layout no es de tamaño cero (HDR > 0).
        let p = unsafe { alloc::alloc(layout) };
        let Some(p) = NonNull::new(p) else { alloc::handle_alloc_error(layout) };
        // SAFETY: `p` es una asignación nueva de `HDR + cap` bytes alineada para `Header`.
        unsafe {
            (p.as_ptr() as *mut Header).write(Header { strong: Cell::new(1), cap });
            std::ptr::copy_nonoverlapping(s.as_ptr(), p.as_ptr().add(HDR), s.len());
        }
        let mut w = [0usize; 2];
        w[PTR_W] = p.as_ptr() as usize;
        w[LEN_W] = s.len();
        let t = SynText { w, _not_send: std::marker::PhantomData };
        debug_assert!(!t.is_inline());
        t
    }

    #[inline]
    pub fn len(&self) -> usize {
        if self.is_inline() {
            (self.bytes()[TAG_BYTE] & !INLINE_BIT) as usize
        } else {
            self.w[LEN_W]
        }
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        let (p, n) = if self.is_inline() {
            // SAFETY: `DATA + len <= 2 * WORD` (en línea, `len <= INLINE_MAX`).
            (unsafe { self.bytes().as_ptr().add(DATA) }, self.len())
        } else {
            (self.heap_ptr() as *const u8, self.w[LEN_W])
        };
        // SAFETY: `[0, n)` es UTF-8 válido (invariante) y vive tanto como `self`.
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(p, n)) }
    }

    /// Si este valor es el único dueño de su texto en el montón (uno en línea no se comparte; uno
    /// inmortal, tampoco: nunca se escribe).
    #[inline]
    pub fn is_unique(&self) -> bool {
        !self.is_inline() && self.header().strong.get() == 1
    }

    /// Lo vuelve inmortal (R2 de specs/modelo-memoria-regiones.md): la cuenta queda en el tope, clonar
    /// y soltar ya no la escriben y la memoria no se libera nunca. Uno en línea no tiene nada que
    /// marcar. Idempotente.
    pub fn make_immortal(&self) {
        if !self.is_inline() && self.header().strong.get() < SCOPED {
            self.header().strong.set(IMMORTAL);
        }
    }

    /// Si está en el montón y es inmortal.
    #[inline]
    pub fn is_immortal(&self) -> bool {
        !self.is_inline() && self.header().strong.get() >= SCOPED
    }

    /// Si es inmortal para siempre (`make_immortal`).
    #[inline]
    pub fn is_permanent(&self) -> bool {
        !self.is_inline() && self.header().strong.get() == IMMORTAL
    }

    /// Si es inmortal con alcance (`make_immortal_logged`): se va a descongelar.
    #[inline]
    pub fn is_scoped(&self) -> bool {
        !self.is_inline() && self.header().strong.get() == SCOPED
    }

    /// `make_immortal` anotando la cuenta que tenía, para devolvérsela (`TextThaw::thaw`, R2.3: un
    /// congelado con alcance). `None` si no había nada que congelar (en línea o ya inmortal).
    pub fn make_immortal_logged(&self) -> Option<TextThaw> {
        if self.is_inline() {
            return None;
        }
        let h = self.header();
        let s = h.strong.get();
        if s >= SCOPED {
            return None;
        }
        h.strong.set(SCOPED);
        Some(TextThaw { header: self.w[PTR_W] as *const Header, strong: s })
    }

    /// Seguro el mismo texto, sin mirar los bytes: los dos valores son idénticos (en línea, los
    /// mismos bytes; en el montón, la misma memoria y el mismo largo). Es la comparación "puntero
    /// primero" de las claves: con claves en línea no hay puntero, pero el valor entero sirve.
    /// `false` no quiere decir distintos (dos copias iguales en el montón).
    #[inline]
    pub fn same(a: &SynText, b: &SynText) -> bool {
        a.w == b.w
    }

    /// La misma memoria en el montón (no una copia igual). Uno en línea no comparte memoria.
    #[inline]
    pub fn ptr_eq(a: &SynText, b: &SynText) -> bool {
        !a.is_inline() && !b.is_inline() && a.w[PTR_W] == b.w[PTR_W]
    }

    /// Agrega `s` al final. Con un solo dueño (o en línea) crece en el lugar: ×2 al quedarse sin
    /// lugar, así que agregar n veces cuesta O(total). Compartido: una copia propia con lugar.
    pub fn push_str(&mut self, s: &str) {
        let len = self.len();
        let need = len.checked_add(s.len()).expect("texto demasiado largo");
        if self.is_inline() {
            if need <= INLINE_MAX {
                let b = self.bytes_mut();
                b[DATA + len..DATA + need].copy_from_slice(s.as_bytes());
                b[TAG_BYTE] = INLINE_BIT | need as u8;
                return;
            }
        } else if self.is_unique() {
            let cap = self.header().cap;
            if need > cap {
                let ncap = need.max(cap.saturating_mul(2));
                let new_layout = Self::layout(ncap);
                // SAFETY: el puntero es una asignación con `layout(cap)`; el tamaño nuevo no es cero.
                let p = unsafe { alloc::realloc(self.w[PTR_W] as *mut u8, Self::layout(cap), new_layout.size()) };
                let Some(p) = NonNull::new(p) else { alloc::handle_alloc_error(new_layout) };
                self.w[PTR_W] = p.as_ptr() as usize;
                // SAFETY: el header se movió junto con la asignación.
                unsafe { (*(p.as_ptr() as *mut Header)).cap = ncap };
            }
            // SAFETY: `[len, need)` entra en la capacidad; nadie más ve estos bytes (único dueño).
            unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), self.heap_ptr().add(len), s.len()) };
            self.w[LEN_W] = need;
            return;
        }
        // En línea que no entra, o compartido: una copia propia del largo justo (una concatenación
        // suelta no deja lugar de más); si su dueño sigue agregando, crece ×2 desde ahí.
        let mut t = SynText::heap_from(self.as_str(), need);
        // SAFETY: `t` es único y tiene lugar para `need`.
        unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), t.heap_ptr().add(len), s.len()) };
        t.w[LEN_W] = need;
        *self = t;
    }
}

impl Default for SynText {
    #[inline]
    fn default() -> SynText {
        SynText::new()
    }
}

/// Un texto que un congelado con alcance volvió inmortal, con la cuenta que tenía (ver
/// `SynText::make_immortal_logged`). Si no se descongela, el texto queda inmortal (una fuga).
pub struct TextThaw {
    header: *const Header,
    strong: usize,
}

impl TextThaw {
    /// Le devuelve la cuenta que tenía.
    ///
    /// # Safety
    /// Lo mismo que `synsema_heap::FreezeLog::thaw`: los clones hechos mientras era inmortal ya se
    /// soltaron, ningún otro hilo lo ve más y el texto sigue vivo (lo sostienen sus dueños).
    pub unsafe fn thaw(self) {
        // SAFETY: lo garantiza quien llama (el texto vive y nadie más lo lee).
        unsafe { (*self.header).strong.set(self.strong) };
    }
}

impl Clone for SynText {
    #[inline]
    fn clone(&self) -> SynText {
        if !self.is_inline() {
            // Sin llamadas (ni la del pánico por desborde): la cuenta llena queda inmortal, una fuga y
            // nunca un uso después de liberar (como `synsema_heap::inc_strong`).
            let h = self.header();
            let s = h.strong.get();
            if s < SCOPED {
                h.strong.set(s + 1);
            }
        }
        SynText { w: self.w, _not_send: std::marker::PhantomData }
    }
}

impl Drop for SynText {
    /// En línea: nada. En el montón: la cuenta baja acá; liberar la memoria va fuera de línea
    /// (como `Rc::drop_slow`), así soltar un valor que no es texto no paga el código de liberar.
    #[inline]
    fn drop(&mut self) {
        if self.is_inline() {
            return;
        }
        let h = self.header();
        let s = h.strong.get();
        // 2 ≤ cuenta < inmortal en una comparación sin signo; el último dueño y el inmortal, aparte.
        if s.wrapping_sub(2) < SCOPED - 2 {
            h.strong.set(s - 1);
        } else if s == 1 {
            self.dealloc_last();
        }
    }
}

impl SynText {
    #[cold]
    #[inline(never)]
    fn dealloc_last(&mut self) {
        let cap = self.header().cap;
        // SAFETY: era la última referencia (la cuenta estaba en 1); la asignación se hizo con
        // `layout(cap)`.
        unsafe { alloc::dealloc(self.w[PTR_W] as *mut u8, Self::layout(cap)) }
    }
}

impl Deref for SynText {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for SynText {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Borrow<str> for SynText {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for SynText {
    #[inline]
    fn from(s: &str) -> SynText {
        if s.len() <= INLINE_MAX {
            SynText::inline_from(s)
        } else {
            SynText::heap_from(s, s.len())
        }
    }
}
impl From<String> for SynText {
    #[inline]
    fn from(s: String) -> SynText {
        SynText::from(s.as_str())
    }
}
impl From<&String> for SynText {
    #[inline]
    fn from(s: &String) -> SynText {
        SynText::from(s.as_str())
    }
}
impl From<Box<str>> for SynText {
    #[inline]
    fn from(s: Box<str>) -> SynText {
        SynText::from(&*s)
    }
}
impl From<char> for SynText {
    #[inline]
    fn from(c: char) -> SynText {
        SynText::from(c.encode_utf8(&mut [0u8; 4]) as &str)
    }
}
impl From<&SynText> for SynText {
    #[inline]
    fn from(s: &SynText) -> SynText {
        s.clone()
    }
}

impl PartialEq for SynText {
    #[inline]
    fn eq(&self, other: &SynText) -> bool {
        SynText::same(self, other) || self.as_str() == other.as_str()
    }
}
impl Eq for SynText {}
impl PartialEq<str> for SynText {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<&str> for SynText {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialOrd for SynText {
    #[inline]
    fn partial_cmp(&self, other: &SynText) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SynText {
    #[inline]
    fn cmp(&self, other: &SynText) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl Hash for SynText {
    #[inline]
    fn hash<H: Hasher>(&self, h: &mut H) {
        // Igual que `str`: lo exige `Borrow<str>`.
        self.as_str().hash(h)
    }
}
/// `write!(t, "{}", x)` agrega en el lugar (como `push_str`).
impl fmt::Write for SynText {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

impl fmt::Debug for SynText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}
impl fmt::Display for SynText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

const _: () = assert!(std::mem::size_of::<SynText>() == 2 * WORD);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_immortal_text_is_never_written_nor_freed() {
        let mut a = SynText::from("un texto largo que vive en el montón");
        a.make_immortal();
        assert!(a.is_immortal() && !a.is_unique());
        let b = a.clone();
        drop(b);
        // Agregar a un inmortal copia: el original no se escribe.
        let c = a.clone();
        a.push_str("!");
        assert_eq!(c.as_str(), "un texto largo que vive en el montón");
        assert!(!a.is_immortal() && a.is_unique());
        // Congelado con alcance: la cuenta vuelve.
        let e = SynText::from("otro texto largo que vive en el montón");
        let e2 = e.clone();
        let t = e.make_immortal_logged().expect("en el montón");
        assert!(e.is_immortal() && e.is_scoped() && e.make_immortal_logged().is_none());
        e.make_immortal();
        assert!(e.is_scoped() && !e.is_permanent(), "con alcance no pasa a permanente");
        drop(e.clone());
        // SAFETY (del test): los clones de la ventana se soltaron; un hilo.
        unsafe { t.thaw() };
        assert!(!e.is_immortal());
        drop(e2);
        assert!(e.is_unique());
        // Uno en línea no tiene nada que marcar.
        let d = SynText::from("corto");
        d.make_immortal();
        assert!(!d.is_immortal());
        // El test devuelve la memoria del inmortal a mano (en el motor vive lo que el proceso).
        let cap = c.header().cap;
        let ptr = c.w[PTR_W] as *mut u8;
        std::mem::forget(c);
        // SAFETY (del test): nadie más tiene el texto; se reservó con `layout(cap)`.
        unsafe { alloc::dealloc(ptr, SynText::layout(cap)) };
    }
}

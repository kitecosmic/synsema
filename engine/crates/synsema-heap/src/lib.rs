//! Objetos del montón de Synsema (R1 de `specs/modelo-memoria-regiones.md`).
//!
//! `Shared<T>` reemplaza a `Rc<RefCell<T>>` en los valores del lenguaje (listas, mapas…), con la
//! misma forma de uso (`borrow`, `borrow_mut`, `strong_count`, `ptr_eq`, `downgrade`…) y tres
//! diferencias:
//! - **Cabecera de 8 bytes** en un solo objeto: cuenta (`u32`), cuenta débil (`u16`) y préstamo
//!   (`i16`). `Rc<RefCell<T>>` usa 24 (dos `usize` de cuentas y un `isize` de préstamo).
//! - **Inmortal** (`make_immortal`): la cuenta queda en `u32::MAX` y ya no cambia. Clonar y soltar no
//!   escriben nada, leer (`borrow`) tampoco (no toca la bandera de préstamo) y escribir
//!   (`borrow_mut`) es un error inmediato. Es lo que deja leer un objeto desde varios hilos sin
//!   carreras (R2: la región compartida). `strong_count` de un inmortal da `usize::MAX`: la copia al
//!   escribir del lenguaje (`make_unique`) lo ve compartido y copia antes de escribir.
//! - Un objeto inmortal no se libera nunca (vive lo que vive el proceso), como los inmortales de
//!   CPython 3.12 (PEP 683).
//!
//! `Shared<T>` no es `Send` ni `Sync` (cuentas no atómicas, como `Rc`). Compartir entre hilos lo
//! hará R2 con un tipo aparte que sólo se puede armar con objetos inmortales.
//!
//! Todo el `unsafe` de los objetos del montón vive en este crate (ver
//! `engine/crates/synsema-jit/tests/unsafe_allowlist.rs`). Invariantes:
//! - `strong` es ≥ 1 mientras exista un `Shared`; `IMMORTAL` = `u32::MAX` no cambia nunca más.
//! - El valor está vivo mientras `strong > 0`; la reserva, mientras `strong > 0` o `weak > 0`.
//! - `borrow` > 0: lectores; `-1`: un escritor; nunca las dos cosas. Un inmortal nunca tiene escritor
//!   y no lleva la cuenta de lectores (siempre 0).

#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{self, Layout};
use std::cell::{Cell, UnsafeCell};
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

/// La cuenta de un objeto inmortal.
const IMMORTAL: u32 = u32::MAX;

/// La cabecera común (8 bytes).
#[repr(C)]
struct Header {
    strong: Cell<u32>,
    weak: Cell<u16>,
    /// > 0: lectores; -1: un escritor; 0: libre.
    borrow: Cell<i16>,
}
const _: () = assert!(std::mem::size_of::<Header>() == 8);

/// Alineado a 8 siempre: R3 (valores de 16 B) puede usar los bits bajos del puntero.
#[repr(C, align(8))]
struct Inner<T> {
    h: Header,
    value: UnsafeCell<T>,
}

/// Un objeto compartido del montón: cuenta propia, préstamos como `RefCell`, y la posibilidad de
/// volverse inmortal. Ver el módulo.
pub struct Shared<T> {
    ptr: NonNull<Inner<T>>,
    _owns: PhantomData<Inner<T>>,
}

/// Una referencia débil: no mantiene vivo el valor (como `rc::Weak`).
pub struct WeakShared<T> {
    ptr: NonNull<Inner<T>>,
    _owns: PhantomData<Inner<T>>,
}

#[cold]
#[inline(never)]
fn overflow() -> ! {
    // Como `Rc`: una cuenta que da la vuelta sería un uso después de liberar.
    std::process::abort()
}

impl<T> Shared<T> {
    pub fn new(value: T) -> Shared<T> {
        let b = Box::new(Inner {
            h: Header { strong: Cell::new(1), weak: Cell::new(0), borrow: Cell::new(0) },
            value: UnsafeCell::new(value),
        });
        Shared { ptr: NonNull::from(Box::leak(b)), _owns: PhantomData }
    }

    #[inline]
    fn header(&self) -> &Header {
        // SAFETY: mientras haya un `Shared`, la reserva está viva (strong ≥ 1).
        unsafe { &self.ptr.as_ref().h }
    }

    /// ¿Es inmortal?
    #[inline]
    pub fn is_immortal(this: &Self) -> bool {
        this.header().strong.get() == IMMORTAL
    }

    /// Lo vuelve inmortal: ya no se libera y nada lo puede escribir. Falla (pánico) si está prestado
    /// para escribir. Idempotente.
    pub fn make_immortal(this: &Self) {
        let h = this.header();
        assert!(h.borrow.get() >= 0, "make_immortal: the value is borrowed for writing");
        h.strong.set(IMMORTAL);
        // Los lectores que hubiera siguen leyendo; sus guardas ya no descuentan (ver `Ref`).
        h.borrow.set(0);
    }

    /// Cuántos `Shared` lo tienen. `usize::MAX` si es inmortal (siempre "compartido").
    #[inline]
    pub fn strong_count(this: &Self) -> usize {
        match this.header().strong.get() {
            IMMORTAL => usize::MAX,
            n => n as usize,
        }
    }

    #[inline]
    pub fn weak_count(this: &Self) -> usize {
        this.header().weak.get() as usize
    }

    #[inline]
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.ptr == b.ptr
    }

    /// Dónde vive el valor (para identidad: registros por dirección).
    #[inline]
    pub fn as_ptr(this: &Self) -> *const T {
        // SAFETY: la reserva está viva; sólo se calcula una dirección.
        unsafe { this.ptr.as_ref().value.get() }
    }

    /// Prestado para leer. Un inmortal no escribe nada.
    #[inline]
    pub fn borrow(&self) -> Ref<'_, T> {
        match self.try_borrow() {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        }
    }

    pub fn try_borrow(&self) -> Result<Ref<'_, T>, BorrowError> {
        let h = self.header();
        let counted = h.strong.get() != IMMORTAL;
        if counted {
            let b = h.borrow.get();
            if b < 0 {
                return Err(BorrowError::Writing);
            }
            if b == i16::MAX {
                return Err(BorrowError::TooManyReaders);
            }
            h.borrow.set(b + 1);
        }
        // SAFETY: no hay escritor (b ≥ 0, o es inmortal y nunca lo tiene); el valor está vivo.
        let value = unsafe { NonNull::new_unchecked(self.ptr.as_ref().value.get()) };
        Ok(Ref { value, release: if counted { Some(h) } else { None }, _life: PhantomData })
    }

    /// Prestado para escribir. Un inmortal no se escribe: pánico (nunca una carrera de datos).
    #[inline]
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        match self.try_borrow_mut() {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        }
    }

    pub fn try_borrow_mut(&self) -> Result<RefMut<'_, T>, BorrowError> {
        let h = self.header();
        if h.strong.get() == IMMORTAL {
            return Err(BorrowError::Immortal);
        }
        match h.borrow.get() {
            0 => {}
            b if b < 0 => return Err(BorrowError::Writing),
            _ => return Err(BorrowError::Reading),
        }
        h.borrow.set(-1);
        // SAFETY: nadie más lo tiene prestado; el valor está vivo.
        let value = unsafe { NonNull::new_unchecked(self.ptr.as_ref().value.get()) };
        Ok(RefMut { value, borrow: &h.borrow, _life: PhantomData })
    }

    /// `&mut` directo si este es el único dueño, sin débiles, sin préstamos y no es inmortal.
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        let h = this.header();
        if h.strong.get() == 1 && h.weak.get() == 0 && h.borrow.get() == 0 {
            // SAFETY: único dueño, sin préstamos: nadie más puede ver el valor.
            Some(unsafe { &mut *this.ptr.as_ref().value.get() })
        } else {
            None
        }
    }

    /// Saca el valor si este es el único dueño (los débiles dejan de poder subir), como
    /// `Rc::try_unwrap`.
    pub fn try_unwrap(this: Self) -> Result<T, Self> {
        let h = this.header();
        if h.strong.get() != 1 || h.borrow.get() != 0 {
            return Err(this);
        }
        h.strong.set(0);
        let ptr = this.ptr;
        std::mem::forget(this);
        // SAFETY: era el único dueño; el valor sale una vez (strong pasó a 0, nadie lo vuelve a leer).
        let value = unsafe { std::ptr::read(ptr.as_ref().value.get()) };
        // SAFETY: strong = 0; si no hay débiles, la reserva ya no tiene a nadie.
        unsafe { release_if_unreferenced(ptr) };
        Ok(value)
    }

    pub fn downgrade(this: &Self) -> WeakShared<T> {
        let h = this.header();
        if h.strong.get() != IMMORTAL {
            let w = h.weak.get();
            if w == u16::MAX {
                overflow();
            }
            h.weak.set(w + 1);
        }
        WeakShared { ptr: this.ptr, _owns: PhantomData }
    }
}

/// Libera la reserva si ya no la tiene nadie (strong = 0 y weak = 0). El valor ya se soltó.
///
/// # Safety
/// `ptr` apunta a una reserva viva de `Inner<T>` cuyo valor ya fue soltado o movido (strong = 0).
unsafe fn release_if_unreferenced<T>(ptr: NonNull<Inner<T>>) {
    // SAFETY: lo garantiza quien llama.
    let h = unsafe { &ptr.as_ref().h };
    if h.strong.get() == 0 && h.weak.get() == 0 {
        // SAFETY: se reservó como `Box<Inner<T>>`; el valor ya no está (ManuallyDrop: no se suelta
        // otra vez), sólo se devuelve la memoria.
        unsafe { alloc::dealloc(ptr.as_ptr().cast(), Layout::new::<Inner<T>>()) };
    }
}

impl<T> Clone for Shared<T> {
    #[inline]
    fn clone(&self) -> Shared<T> {
        let h = self.header();
        let s = h.strong.get();
        if s != IMMORTAL {
            if s == IMMORTAL - 1 {
                overflow();
            }
            h.strong.set(s + 1);
        }
        Shared { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T> Drop for Shared<T> {
    #[inline]
    fn drop(&mut self) {
        let h = self.header();
        let s = h.strong.get();
        if s == IMMORTAL {
            return;
        }
        h.strong.set(s - 1);
        if s == 1 {
            // SAFETY: era el último dueño: el valor se suelta una vez. Nadie lo tiene prestado (un
            // préstamo vive menos que el `Shared` del que salió).
            unsafe { std::ptr::drop_in_place(self.ptr.as_ref().value.get()) };
            // SAFETY: strong = 0 y el valor ya se soltó.
            unsafe { release_if_unreferenced(self.ptr) };
        }
    }
}

impl<T> WeakShared<T> {
    #[inline]
    fn header(&self) -> &Header {
        // SAFETY: mientras haya un débil, la reserva está viva (weak ≥ 1, o el objeto es inmortal).
        unsafe { &self.ptr.as_ref().h }
    }

    /// Un `Shared` si el valor sigue vivo.
    pub fn upgrade(&self) -> Option<Shared<T>> {
        let h = self.header();
        match h.strong.get() {
            0 => None,
            IMMORTAL => Some(Shared { ptr: self.ptr, _owns: PhantomData }),
            s => {
                if s == IMMORTAL - 1 {
                    overflow();
                }
                h.strong.set(s + 1);
                Some(Shared { ptr: self.ptr, _owns: PhantomData })
            }
        }
    }

    pub fn strong_count(&self) -> usize {
        match self.header().strong.get() {
            IMMORTAL => usize::MAX,
            n => n as usize,
        }
    }
}

impl<T> Clone for WeakShared<T> {
    fn clone(&self) -> WeakShared<T> {
        let h = self.header();
        if h.strong.get() != IMMORTAL {
            let w = h.weak.get();
            if w == u16::MAX {
                overflow();
            }
            h.weak.set(w + 1);
        }
        WeakShared { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T> Drop for WeakShared<T> {
    fn drop(&mut self) {
        let h = self.header();
        if h.strong.get() == IMMORTAL {
            return;
        }
        h.weak.set(h.weak.get() - 1);
        // SAFETY: si strong = 0 el valor ya se soltó; libera si también era el último débil.
        unsafe { release_if_unreferenced(self.ptr) };
    }
}

/// Por qué no se pudo prestar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowError {
    /// Está prestado para escribir.
    Writing,
    /// Está prestado para leer (y se pidió escribir).
    Reading,
    /// Demasiados lectores a la vez (más de `i16::MAX`).
    TooManyReaders,
    /// Es inmortal: no se escribe nunca (se copia antes; ver `make_unique` en el intérprete).
    Immortal,
}

impl fmt::Display for BorrowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BorrowError::Writing => "already mutably borrowed",
            BorrowError::Reading => "already borrowed",
            BorrowError::TooManyReaders => "too many readers of one value",
            BorrowError::Immortal => "an immortal value cannot be written (copy it first)",
        })
    }
}

/// Préstamo para leer (como `cell::Ref`).
pub struct Ref<'b, T: ?Sized> {
    value: NonNull<T>,
    /// La cabecera, para descontar al soltar; `None` si era inmortal al prestarse. Si se vuelve
    /// inmortal mientras tanto, la guarda lo ve en la cabecera y no descuenta.
    release: Option<&'b Header>,
    _life: PhantomData<&'b T>,
}

impl<'b, T: ?Sized> Ref<'b, T> {
    /// Un préstamo de una parte (como `cell::Ref::map`).
    pub fn map<U: ?Sized>(orig: Ref<'b, T>, f: impl FnOnce(&T) -> &U) -> Ref<'b, U> {
        // SAFETY: el préstamo de `orig` sigue vigente y pasa al nuevo (no se libera dos veces).
        let value = NonNull::from(f(unsafe { orig.value.as_ref() }));
        let release = orig.release;
        std::mem::forget(orig);
        Ref { value, release, _life: PhantomData }
    }

    /// Como `cell::Ref::clone`: otro lector del mismo préstamo.
    pub fn clone(orig: &Ref<'b, T>) -> Ref<'b, T> {
        if let Some(h) = orig.release {
            if h.strong.get() != IMMORTAL {
                let n = h.borrow.get();
                if n == i16::MAX {
                    panic!("{}", BorrowError::TooManyReaders);
                }
                h.borrow.set(n + 1);
            }
        }
        Ref { value: orig.value, release: orig.release, _life: PhantomData }
    }
}

impl<T: ?Sized> Deref for Ref<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: prestado para leer mientras viva la guarda.
        unsafe { self.value.as_ref() }
    }
}

impl<T: ?Sized> Drop for Ref<'_, T> {
    #[inline]
    fn drop(&mut self) {
        if let Some(h) = self.release {
            if h.strong.get() != IMMORTAL {
                h.borrow.set(h.borrow.get() - 1);
            }
        }
    }
}

/// Préstamo para escribir (como `cell::RefMut`).
pub struct RefMut<'b, T: ?Sized> {
    value: NonNull<T>,
    borrow: &'b Cell<i16>,
    _life: PhantomData<&'b mut T>,
}

impl<'b, T: ?Sized> RefMut<'b, T> {
    /// Un préstamo de una parte (como `cell::RefMut::map`).
    pub fn map<U: ?Sized>(mut orig: RefMut<'b, T>, f: impl FnOnce(&mut T) -> &mut U) -> RefMut<'b, U> {
        // SAFETY: el préstamo exclusivo de `orig` pasa al nuevo (no se libera dos veces).
        let value = NonNull::from(f(unsafe { orig.value.as_mut() }));
        let borrow = orig.borrow;
        std::mem::forget(orig);
        RefMut { value, borrow, _life: PhantomData }
    }
}

impl<T: ?Sized> Deref for RefMut<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: prestado en exclusiva mientras viva la guarda.
        unsafe { self.value.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for RefMut<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: prestado en exclusiva mientras viva la guarda.
        unsafe { self.value.as_mut() }
    }
}

impl<T: ?Sized> Drop for RefMut<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.borrow.set(0);
    }
}

impl<T: fmt::Debug> fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_borrow() {
            Ok(v) => fmt::Debug::fmt(&*v, f),
            Err(_) => f.write_str("<borrowed>"),
        }
    }
}

// =============================================================================================
// Objetos de tamaño variable con puntero fino (R1.2): un campo fijo + una lista en línea al final
// =============================================================================================

/// Un tipo de tamaño variable `S<[Elem]>` cuyo primer campo es `Head` y el último una lista
/// `[Elem]` en línea (`repr(C)`, sólo esos dos campos): el cuerpo de un mapa con sus valores en
/// línea (F4.5). **No se implementa a mano: lo hace `tail_object!`**, que verifica la forma del tipo
/// al compilar.
///
/// # Safety
/// `HEAD_OFFSET`, `TAIL_OFFSET` y `ALIGN` son los de `S<[Elem; 0]>`, `S` es `repr(C)` con sólo
/// esos dos campos, y `from_raw_parts` arma el puntero gordo con la dirección dada y `len`.
pub unsafe trait TailObject {
    type Head;
    type Elem;
    const HEAD_OFFSET: usize;
    const TAIL_OFFSET: usize;
    const ALIGN: usize;
    /// El puntero gordo al objeto que empieza en `addr` y tiene `len` elementos.
    fn from_raw_parts(addr: *mut u8, len: usize) -> *mut Self;
}

/// `S<[Elem]>` es un `TailObject`. Uso: `tail_object!(MapBody, layout: Option<Rc<Node>>, vals: [SynValue])`
/// con `#[repr(C)] struct MapBody<S: ?Sized> { layout: Option<Rc<Node>>, vals: S }`. Verifica al
/// compilar que el campo fijo esté al principio, que la lista lo siga sin otro campo en el medio y
/// que no haya nada después: si no, no compila.
///
/// Un campo de más en el medio no compila:
/// ```compile_fail,E0080
/// #[repr(C)]
/// struct Bad<S: ?Sized> { head: u64, extra: u64, tail: S }
/// synsema_heap::tail_object!(Bad, head: u64, tail: [u64]);
/// ```
/// El campo fijo tiene que ir primero:
/// ```compile_fail,E0080
/// #[repr(C)]
/// struct Bad<S: ?Sized> { other: u32, head: u32, tail: S }
/// synsema_heap::tail_object!(Bad, head: u32, tail: [u64]);
/// ```
/// La forma correcta compila:
/// ```
/// #[repr(C)]
/// struct Good<S: ?Sized> { head: u32, tail: S }
/// synsema_heap::tail_object!(Good, head: u32, tail: [u64]);
/// let g: synsema_heap::SharedTail<Good<[u64]>> = synsema_heap::SharedTail::new(7, 3, |i| i as u64);
/// assert_eq!(g.borrow().tail[2], 2);
/// ```
#[macro_export]
macro_rules! tail_object {
    ($ty:ident, $head_field:ident : $head:ty, $tail_field:ident : [$elem:ty]) => {
        // SAFETY: la macro y su verificación viven en synsema-heap (ver `TailObject`); las
        // aserciones de abajo fijan la forma que ese contrato pide.
        unsafe impl $crate::TailObject for $ty<[$elem]> {
            type Head = $head;
            type Elem = $elem;
            const HEAD_OFFSET: usize = ::core::mem::offset_of!($ty<[$elem; 0]>, $head_field);
            const TAIL_OFFSET: usize = ::core::mem::offset_of!($ty<[$elem; 0]>, $tail_field);
            const ALIGN: usize = ::core::mem::align_of::<$ty<[$elem; 0]>>();
            #[inline]
            fn from_raw_parts(addr: *mut u8, len: usize) -> *mut Self {
                ::core::ptr::slice_from_raw_parts_mut(addr.cast::<$elem>(), len) as *mut Self
            }
        }
        const _: () = $crate::check_tail_layout(
            ::core::mem::offset_of!($ty<[$elem; 0]>, $head_field),
            ::core::mem::size_of::<$head>(),
            ::core::mem::offset_of!($ty<[$elem; 0]>, $tail_field),
            ::core::mem::align_of::<$elem>(),
            ::core::mem::size_of::<$ty<[$elem; 0]>>(),
            ::core::mem::align_of::<$ty<[$elem; 0]>>(),
        );
    };
}

/// La verificación de `tail_object!` (en tiempo de compilación): el campo fijo en 0, la lista justo
/// después (redondeada a su alineación) y el tamaño del tipo vacío = eso redondeado a su alineación.
#[doc(hidden)]
pub const fn check_tail_layout(head_off: usize, head_size: usize, tail_off: usize, elem_align: usize, size0: usize, align: usize) {
    assert!(head_off == 0, "tail_object!: the fixed field must come first (is the type repr(C)?)");
    assert!(tail_off == head_size.div_ceil(elem_align) * elem_align, "tail_object!: the list must follow the fixed field, with nothing in between");
    assert!(size0 == tail_off.div_ceil(align) * align, "tail_object!: nothing may come after the list");
}

/// Cabecera + largo, antes del objeto.
#[repr(C, align(8))]
struct TailPrefix {
    h: Header,
    len: usize,
}

/// Un objeto compartido de tamaño variable con puntero FINO (el largo vive en el objeto). La misma
/// forma de uso que `Shared<T>`.
pub struct SharedTail<T: ?Sized + TailObject> {
    ptr: NonNull<TailPrefix>,
    _owns: PhantomData<T>,
}

/// Una referencia débil a un `SharedTail`.
pub struct WeakTail<T: ?Sized + TailObject> {
    ptr: NonNull<TailPrefix>,
    _owns: PhantomData<T>,
}

/// Dónde empieza el objeto y la reserva entera, para `len` elementos.
fn tail_layout<T: ?Sized + TailObject>(len: usize) -> (usize, Layout) {
    let align = T::ALIGN.max(std::mem::align_of::<TailPrefix>());
    let obj_off = std::mem::size_of::<TailPrefix>().div_ceil(T::ALIGN) * T::ALIGN;
    let tail_bytes = std::mem::size_of::<T::Elem>().checked_mul(len).expect("tail object too large");
    let obj_size = (T::TAIL_OFFSET + tail_bytes).div_ceil(T::ALIGN) * T::ALIGN;
    let total = obj_off.checked_add(obj_size).expect("tail object too large");
    (obj_off, Layout::from_size_align(total, align).expect("tail object layout"))
}

/// Si `fill` entra en pánico a mitad de armar un `SharedTail`: suelta los elementos escritos, el
/// campo fijo y la reserva.
struct Partial<H, E> {
    head: *mut H,
    tail: *mut E,
    done: usize,
    base: *mut u8,
    layout: Layout,
}

impl<H, E> Drop for Partial<H, E> {
    fn drop(&mut self) {
        // SAFETY: sólo lo ya escrito: el campo fijo y `done` elementos; la reserva es la de `layout`.
        unsafe {
            std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(self.tail, self.done));
            std::ptr::drop_in_place(self.head);
            alloc::dealloc(self.base, self.layout);
        }
    }
}

impl<T: ?Sized + TailObject> SharedTail<T> {
    /// Arma el objeto: el campo fijo `head` y `len` elementos, el `i` de `fill(i)`. Si `fill` entra
    /// en pánico, lo ya armado se suelta y la reserva se devuelve.
    pub fn new(head: T::Head, len: usize, mut fill: impl FnMut(usize) -> T::Elem) -> SharedTail<T> {
        let (obj_off, layout) = tail_layout::<T>(len);
        // SAFETY: el tamaño es > 0 (al menos el prefijo).
        let raw = unsafe { alloc::alloc(layout) };
        let Some(base) = NonNull::new(raw) else { alloc::handle_alloc_error(layout) };
        // SAFETY: la reserva tiene lugar y alineación para el prefijo.
        unsafe {
            base.cast::<TailPrefix>().as_ptr().write(TailPrefix {
                h: Header { strong: Cell::new(1), weak: Cell::new(0), borrow: Cell::new(0) },
                len,
            })
        };
        // SAFETY: los offsets son los del tipo (verificados por `tail_object!`), dentro de la reserva.
        let (head_p, tail) = unsafe {
            let obj = base.as_ptr().add(obj_off);
            (obj.add(T::HEAD_OFFSET).cast::<T::Head>(), obj.add(T::TAIL_OFFSET).cast::<T::Elem>())
        };
        // SAFETY: el lugar del campo fijo, sin escribir todavía.
        unsafe { head_p.write(head) };
        let mut partial: Partial<T::Head, T::Elem> = Partial { head: head_p, tail, done: 0, base: base.as_ptr(), layout };
        for i in 0..len {
            let e = fill(i);
            // SAFETY: el lugar `i` de la lista, dentro de la reserva, todavía sin escribir.
            unsafe { tail.add(i).write(e) };
            partial.done = i + 1;
        }
        std::mem::forget(partial);
        let s = SharedTail { ptr: base.cast(), _owns: PhantomData };
        // SAFETY: el objeto está entero; sólo se mide (el tamaño que ve Rust = el reservado).
        debug_assert_eq!(unsafe { std::mem::size_of_val(&*s.obj_ptr()) }, layout.size() - obj_off);
        s
    }

    #[inline]
    fn header(&self) -> &Header {
        // SAFETY: la reserva está viva mientras haya un `SharedTail`.
        unsafe { &self.ptr.as_ref().h }
    }

    #[inline]
    fn obj_ptr(&self) -> *mut T {
        // SAFETY: la reserva está viva; sólo se calcula la dirección del objeto.
        let len = unsafe { self.ptr.as_ref().len };
        let (obj_off, _) = tail_layout::<T>(len);
        T::from_raw_parts(unsafe { self.ptr.as_ptr().cast::<u8>().add(obj_off) }, len)
    }

    /// Cuántos elementos tiene la lista en línea.
    #[inline]
    pub fn tail_len(this: &Self) -> usize {
        // SAFETY: la reserva está viva.
        unsafe { this.ptr.as_ref().len }
    }

    #[inline]
    pub fn is_immortal(this: &Self) -> bool {
        this.header().strong.get() == IMMORTAL
    }
    pub fn make_immortal(this: &Self) {
        make_immortal_h(this.header());
    }
    #[inline]
    pub fn strong_count(this: &Self) -> usize {
        strong_count_h(this.header())
    }
    #[inline]
    pub fn weak_count(this: &Self) -> usize {
        this.header().weak.get() as usize
    }
    #[inline]
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.ptr == b.ptr
    }
    #[inline]
    pub fn as_ptr(this: &Self) -> *const T {
        this.obj_ptr()
    }

    #[inline]
    pub fn borrow(&self) -> Ref<'_, T> {
        match self.try_borrow() {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        }
    }
    pub fn try_borrow(&self) -> Result<Ref<'_, T>, BorrowError> {
        let h = self.header();
        let counted = take_read(h)?;
        // SAFETY: no hay escritor; el objeto está vivo.
        let value = unsafe { NonNull::new_unchecked(self.obj_ptr()) };
        Ok(Ref { value, release: if counted { Some(h) } else { None }, _life: PhantomData })
    }
    #[inline]
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        match self.try_borrow_mut() {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        }
    }
    pub fn try_borrow_mut(&self) -> Result<RefMut<'_, T>, BorrowError> {
        let h = self.header();
        take_write(h)?;
        // SAFETY: nadie más lo tiene prestado; el objeto está vivo.
        let value = unsafe { NonNull::new_unchecked(self.obj_ptr()) };
        Ok(RefMut { value, borrow: &h.borrow, _life: PhantomData })
    }
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        let h = this.header();
        if h.strong.get() == 1 && h.weak.get() == 0 && h.borrow.get() == 0 {
            // SAFETY: único dueño, sin préstamos.
            Some(unsafe { &mut *this.obj_ptr() })
        } else {
            None
        }
    }
    pub fn downgrade(this: &Self) -> WeakTail<T> {
        inc_weak(this.header());
        WeakTail { ptr: this.ptr, _owns: PhantomData }
    }

    /// # Safety
    /// El objeto ya se soltó (strong = 0).
    unsafe fn release_if_unreferenced(ptr: NonNull<TailPrefix>) {
        // SAFETY: la reserva sigue viva hasta acá.
        let (h, len) = unsafe { (&ptr.as_ref().h, ptr.as_ref().len) };
        if h.strong.get() == 0 && h.weak.get() == 0 {
            let (_, layout) = tail_layout::<T>(len);
            // SAFETY: la reserva se hizo con este mismo layout.
            unsafe { alloc::dealloc(ptr.as_ptr().cast(), layout) };
        }
    }
}

impl<T: ?Sized + TailObject> Clone for SharedTail<T> {
    #[inline]
    fn clone(&self) -> Self {
        inc_strong(self.header());
        SharedTail { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T: ?Sized + TailObject> Drop for SharedTail<T> {
    #[inline]
    fn drop(&mut self) {
        if dec_strong(self.header()) {
            // SAFETY: era el último dueño: el objeto se suelta una vez (nadie lo tiene prestado: un
            // préstamo vive menos que el `SharedTail` del que salió).
            unsafe { std::ptr::drop_in_place(self.obj_ptr()) };
            // SAFETY: el objeto ya se soltó.
            unsafe { Self::release_if_unreferenced(self.ptr) };
        }
    }
}

impl<T: ?Sized + TailObject> WeakTail<T> {
    pub fn upgrade(&self) -> Option<SharedTail<T>> {
        // SAFETY: la reserva vive mientras haya un débil.
        let h = unsafe { &self.ptr.as_ref().h };
        upgrade_h(h).then(|| SharedTail { ptr: self.ptr, _owns: PhantomData })
    }
}

impl<T: ?Sized + TailObject> Clone for WeakTail<T> {
    fn clone(&self) -> Self {
        // SAFETY: la reserva vive mientras haya un débil.
        inc_weak(unsafe { &self.ptr.as_ref().h });
        WeakTail { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T: ?Sized + TailObject> Drop for WeakTail<T> {
    fn drop(&mut self) {
        // SAFETY: la reserva vive mientras haya un débil.
        let h = unsafe { &self.ptr.as_ref().h };
        if dec_weak(h) {
            // SAFETY: strong = 0 (el objeto ya se soltó) y era el último débil.
            unsafe { SharedTail::<T>::release_if_unreferenced(self.ptr) };
        }
    }
}

// --- operaciones de cabecera de `SharedTail` ---

#[inline]
fn inc_strong(h: &Header) {
    let s = h.strong.get();
    if s != IMMORTAL {
        if s == IMMORTAL - 1 {
            overflow();
        }
        h.strong.set(s + 1);
    }
}
/// `true` si era el último dueño (y no es inmortal).
#[inline]
fn dec_strong(h: &Header) -> bool {
    let s = h.strong.get();
    if s == IMMORTAL {
        return false;
    }
    h.strong.set(s - 1);
    s == 1
}
fn inc_weak(h: &Header) {
    if h.strong.get() != IMMORTAL {
        let w = h.weak.get();
        if w == u16::MAX {
            overflow();
        }
        h.weak.set(w + 1);
    }
}
/// `true` si después de descontar no queda nadie (hay que mirar la reserva).
fn dec_weak(h: &Header) -> bool {
    if h.strong.get() == IMMORTAL {
        return false;
    }
    h.weak.set(h.weak.get() - 1);
    h.strong.get() == 0 && h.weak.get() == 0
}
fn upgrade_h(h: &Header) -> bool {
    if h.strong.get() == 0 {
        return false;
    }
    inc_strong(h);
    true
}
fn strong_count_h(h: &Header) -> usize {
    match h.strong.get() {
        IMMORTAL => usize::MAX,
        n => n as usize,
    }
}
fn make_immortal_h(h: &Header) {
    assert!(h.borrow.get() >= 0, "make_immortal: the value is borrowed for writing");
    h.strong.set(IMMORTAL);
    h.borrow.set(0);
}
/// Toma un lector; `Ok(true)` si se cuenta (no inmortal).
#[inline]
fn take_read(h: &Header) -> Result<bool, BorrowError> {
    if h.strong.get() == IMMORTAL {
        return Ok(false);
    }
    let b = h.borrow.get();
    if b < 0 {
        return Err(BorrowError::Writing);
    }
    if b == i16::MAX {
        return Err(BorrowError::TooManyReaders);
    }
    h.borrow.set(b + 1);
    Ok(true)
}
#[inline]
fn take_write(h: &Header) -> Result<(), BorrowError> {
    if h.strong.get() == IMMORTAL {
        return Err(BorrowError::Immortal);
    }
    match h.borrow.get() {
        0 => {
            h.borrow.set(-1);
            Ok(())
        }
        b if b < 0 => Err(BorrowError::Writing),
        _ => Err(BorrowError::Reading),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    /// Cuenta cuántas veces se soltó (para ver que el valor se suelta una vez, en el momento justo).
    struct Probe(Rc<Cell<u32>>);
    impl Drop for Probe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn header_is_eight_bytes_and_pointer_is_thin() {
        assert_eq!(std::mem::size_of::<Header>(), 8);
        assert_eq!(std::mem::size_of::<Shared<u64>>(), std::mem::size_of::<usize>());
        assert_eq!(std::mem::size_of::<Option<Shared<u64>>>(), std::mem::size_of::<usize>());
        // Listo para R3 (valores de 16 B, etiqueta en bits bajos posible): reservas alineadas a 8.
        assert_eq!(std::mem::align_of::<Inner<u8>>(), 8);
        let s = Shared::new(1u64);
        assert_eq!(Shared::as_ptr(&s) as usize % std::mem::align_of::<u64>(), 0);
    }

    #[test]
    fn counts_and_drop_once() {
        let drops = Rc::new(Cell::new(0));
        let a = Shared::new(Probe(drops.clone()));
        let b = a.clone();
        assert_eq!(Shared::strong_count(&a), 2);
        assert!(Shared::ptr_eq(&a, &b));
        drop(a);
        assert_eq!(drops.get(), 0);
        assert_eq!(Shared::strong_count(&b), 1);
        drop(b);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn borrows_follow_refcell_rules() {
        let a = Shared::new(vec![1, 2, 3]);
        {
            let r1 = a.borrow();
            let r2 = a.borrow();
            assert_eq!(r1.len() + r2.len(), 6);
            assert_eq!(a.try_borrow_mut().err(), Some(BorrowError::Reading));
        }
        {
            let mut w = a.borrow_mut();
            w.push(4);
            assert_eq!(a.try_borrow().err(), Some(BorrowError::Writing));
            assert_eq!(a.try_borrow_mut().err(), Some(BorrowError::Writing));
        }
        assert_eq!(*a.borrow(), vec![1, 2, 3, 4]);
        // map de lectura y de escritura
        let first = Ref::map(a.borrow(), |v| &v[0]);
        assert_eq!(*first, 1);
        drop(first);
        *RefMut::map(a.borrow_mut(), |v| &mut v[1]) = 20;
        assert_eq!(a.borrow()[1], 20);
        let r = a.borrow();
        let r2 = Ref::clone(&r);
        drop(r);
        assert_eq!(a.try_borrow_mut().err(), Some(BorrowError::Reading));
        drop(r2);
        assert!(a.try_borrow_mut().is_ok());
    }

    #[test]
    fn immortal_never_writes_and_never_drops() {
        let drops = Rc::new(Cell::new(0));
        let a = Shared::new(Probe(drops.clone()));
        Shared::make_immortal(&a);
        assert!(Shared::is_immortal(&a));
        assert_eq!(Shared::strong_count(&a), usize::MAX);
        let ptr = a.ptr;
        let b = a.clone();
        let c = b.clone();
        // Ni la cuenta ni la bandera de préstamo cambian al clonar o leer.
        let read = |s: &Shared<Probe>| (s.header().strong.get(), s.header().borrow.get());
        assert_eq!(read(&a), (IMMORTAL, 0));
        {
            let _r1 = a.borrow();
            let _r2 = c.borrow();
            assert_eq!(read(&a), (IMMORTAL, 0));
        }
        assert_eq!(a.try_borrow_mut().err(), Some(BorrowError::Immortal));
        let w = Shared::downgrade(&a);
        assert!(w.upgrade().is_some());
        assert_eq!(Shared::weak_count(&a), 0);
        drop((a, b, c, w));
        assert_eq!(drops.get(), 0);
        // Inmortal: la reserva sigue (no se libera nunca). Se lee igual.
        // SAFETY (del test): la reserva no se liberó.
        assert_eq!(unsafe { ptr.as_ref().h.strong.get() }, IMMORTAL);
        // El test devuelve la memoria a mano (en el motor, vive lo que el proceso).
        unsafe {
            std::ptr::drop_in_place(ptr.as_ref().value.get());
            alloc::dealloc(ptr.as_ptr().cast(), Layout::new::<Inner<Probe>>());
        }
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn readers_alive_when_made_immortal_do_not_underflow() {
        let a = Shared::new(5u32);
        let r = a.borrow();
        Shared::make_immortal(&a);
        drop(r); // su guarda ya no descuenta: la bandera queda en 0
        assert_eq!(a.header().borrow.get(), 0);
        assert_eq!(*a.borrow(), 5);
        // la reserva del test
        let ptr = a.ptr;
        drop(a);
        unsafe { alloc::dealloc(ptr.as_ptr().cast(), Layout::new::<Inner<u32>>()) };
    }

    #[test]
    #[should_panic(expected = "borrowed for writing")]
    fn cannot_make_immortal_while_written() {
        let a = Shared::new(1u8);
        let _w = a.borrow_mut();
        Shared::make_immortal(&a);
    }

    #[test]
    fn weak_keeps_allocation_not_value() {
        let drops = Rc::new(Cell::new(0));
        let a = Shared::new(Probe(drops.clone()));
        let w = Shared::downgrade(&a);
        let w2 = w.clone();
        assert_eq!(Shared::weak_count(&a), 2);
        assert!(w.upgrade().is_some());
        drop(a);
        assert_eq!(drops.get(), 1);
        assert!(w.upgrade().is_none());
        assert_eq!(w.strong_count(), 0);
        drop(w);
        drop(w2); // el último débil libera la reserva (Miri: sin fugas ni uso después de liberar)
    }

    #[test]
    fn get_mut_and_try_unwrap() {
        let mut a = Shared::new(String::from("x"));
        Shared::get_mut(&mut a).unwrap().push('y');
        let b = a.clone();
        assert!(Shared::get_mut(&mut a).is_none());
        let a = Shared::try_unwrap(a).unwrap_err();
        drop(b);
        let w = Shared::downgrade(&a);
        assert_eq!(Shared::try_unwrap(a).unwrap(), "xy");
        assert!(w.upgrade().is_none()); // el valor salió; el débil ya no sube
        drop(w);
        let s = Shared::new(String::from("z"));
        let r = s.borrow();
        drop(r);
        assert_eq!(Shared::try_unwrap(s).unwrap(), "z");
    }

    // --- R1.2: objetos de tamaño variable ---

    /// Como el cuerpo de un mapa: la forma (un `Rc`) y los valores en línea.
    #[repr(C)]
    struct Row<S: ?Sized> {
        shape: Option<Rc<u32>>,
        vals: S,
    }
    crate::tail_object!(Row, shape: Option<Rc<u32>>, vals: [Probe]);

    /// Alineaciones mezcladas: campo fijo de 1 B, elementos de 8.
    #[repr(C)]
    struct Odd<S: ?Sized> {
        tag: u8,
        items: S,
    }
    crate::tail_object!(Odd, tag: u8, items: [u64]);

    #[test]
    fn tail_objects_are_thin_and_hold_their_values() {
        assert_eq!(std::mem::size_of::<SharedTail<Row<[Probe]>>>(), std::mem::size_of::<usize>());
        let drops = Rc::new(Cell::new(0));
        let shape = Rc::new(7u32);
        for len in [0usize, 1, 5, 33] {
            let d = drops.clone();
            let r: SharedTail<Row<[Probe]>> = SharedTail::new(Some(shape.clone()), len, move |_| Probe(d.clone()));
            assert_eq!(SharedTail::tail_len(&r), len);
            {
                let b = r.borrow();
                assert_eq!(b.vals.len(), len);
                assert_eq!(**b.shape.as_ref().unwrap(), 7);
            }
            let r2 = r.clone();
            assert_eq!(SharedTail::strong_count(&r), 2);
            drop(r);
            assert_eq!(drops.get() as usize, 0);
            drop(r2);
            assert_eq!(drops.get() as usize, len);
            drops.set(0);
        }
        assert_eq!(Rc::strong_count(&shape), 1);

        let o: SharedTail<Odd<[u64]>> = SharedTail::new(3u8, 4, |i| (i as u64) * 10);
        o.borrow_mut().items[2] = 99;
        let b = o.borrow();
        assert_eq!((b.tag, &b.items[..]), (3, &[0, 10, 99, 30][..]));
        assert_eq!(SharedTail::as_ptr(&o).cast::<u8>() as usize % 8, 0);
    }

    #[test]
    fn tail_objects_immortal_weak_and_borrows() {
        let drops = Rc::new(Cell::new(0));
        let d = drops.clone();
        let r: SharedTail<Row<[Probe]>> = SharedTail::new(None, 3, move |_| Probe(d.clone()));
        let w = SharedTail::downgrade(&r);
        {
            let _a = r.borrow();
            assert_eq!(r.try_borrow_mut().err(), Some(BorrowError::Reading));
        }
        assert!(w.upgrade().is_some());
        drop(r);
        assert_eq!(drops.get(), 3);
        assert!(w.upgrade().is_none());
        drop(w);

        let i: SharedTail<Odd<[u64]>> = SharedTail::new(1u8, 2, |_| 5);
        SharedTail::make_immortal(&i);
        assert_eq!(SharedTail::strong_count(&i), usize::MAX);
        let c = i.clone();
        assert_eq!(c.borrow().items[1], 5);
        assert_eq!(i.try_borrow_mut().err(), Some(BorrowError::Immortal));
        // El test devuelve la reserva a mano (en el motor, un inmortal vive lo que el proceso).
        let ptr = i.ptr;
        drop((i, c));
        let (_, layout) = tail_layout::<Odd<[u64]>>(2);
        unsafe { alloc::dealloc(ptr.as_ptr().cast(), layout) };
    }

    #[test]
    fn tail_fill_panic_releases_everything() {
        let drops = Rc::new(Cell::new(0));
        let shape = Rc::new(1u32);
        let d = drops.clone();
        let s2 = shape.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _r: SharedTail<Row<[Probe]>> = SharedTail::new(Some(s2), 6, |i| {
                if i == 4 {
                    panic!("a la mitad");
                }
                Probe(d.clone())
            });
        }));
        assert!(r.is_err());
        // Los 4 elementos escritos y el campo fijo se soltaron; Miri verifica que la reserva volvió.
        assert_eq!(drops.get(), 4);
        assert_eq!(Rc::strong_count(&shape), 1);
    }

    #[test]
    fn many_objects_and_nested_values() {
        // Listas de objetos que tienen objetos (como listas de mapas): sin fugas ni dobles liberaciones.
        let drops = Rc::new(Cell::new(0));
        let rows: Vec<Shared<Vec<Shared<Probe>>>> = (0..50)
            .map(|_| Shared::new((0..3).map(|_| Shared::new(Probe(drops.clone()))).collect()))
            .collect();
        let copy = rows.clone();
        let inner = rows[7].borrow()[1].clone();
        drop(rows);
        assert_eq!(drops.get(), 0);
        drop(copy);
        assert_eq!(drops.get(), 149);
        drop(inner);
        assert_eq!(drops.get(), 150);
    }
}

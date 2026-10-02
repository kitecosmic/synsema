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
//! `Obj<T>` y `ObjSlice<E>` son la versión de sólo lectura (reemplazan a `Rc<T>` y `Rc<[E]>`): la
//! misma cabecera y el mismo inmortal, leídos con `Deref` sin bandera de préstamo; `ObjSlice` con
//! puntero fino.
//!
//! `Shared<T>` no es `Send` ni `Sync` (cuentas no atómicas, como `Rc`). Compartir entre hilos lo
//! hará R2 con un tipo aparte que sólo se puede armar con objetos inmortales.
//!
//! Todo el `unsafe` de los objetos del montón vive en este crate (ver
//! `engine/crates/synsema-jit/tests/unsafe_allowlist.rs`). Invariantes:
//! - `strong` es ≥ 1 mientras exista un `Shared`; `IMMORTAL` = `u32::MAX` no cambia nunca más (se
//!   llega por `make_immortal` o porque la cuenta se llenó: ver `inc_strong`).
//! - El valor está vivo mientras `strong > 0`; la reserva, mientras `strong > 0` o `weak > 0`.
//! - `borrow` > 0: lectores; `-1`: un escritor; nunca las dos cosas. Un inmortal tiene la bandera fija
//!   en `IMMORTAL_BORROW` (el tope): los caminos rápidos de leer y escribir la rechazan con la misma
//!   comparación que ya hacen, así que el inmortal no cuesta nada en el camino normal.
//! - Sólo se vuelve inmortal un objeto que nadie tiene prestado (`make_immortal`).

#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{self, Layout};
use std::cell::{Cell, UnsafeCell};
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

/// La cuenta de un objeto inmortal.
const IMMORTAL: u32 = u32::MAX;
/// La bandera de préstamo de un objeto inmortal: el tope de lectores. Ver el módulo.
const IMMORTAL_BORROW: i16 = i16::MAX;
/// La bandera de préstamo de un inmortal CON ALCANCE (R2.3, `FreezeLog`): se descongela al terminar,
/// así que no puede pasar a una región permanente (`is_scoped`). Los caminos rápidos la rechazan
/// igual que al inmortal: los lectores cuentan hasta antes de ella.
const SCOPED_BORROW: i16 = i16::MAX - 1;

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

    /// Lo vuelve inmortal: ya no se libera y nada lo puede escribir. Falla (pánico) si alguien lo
    /// tiene prestado (congelar ocurre en un punto quieto). Idempotente.
    pub fn make_immortal(this: &Self) {
        make_immortal_h(this.header());
    }

    /// `make_immortal` anotando la cuenta que tenía en `log`, para devolvérsela con `FreezeLog::thaw`
    /// (R2.3: un congelado con alcance). Lo que ya era inmortal no se anota: no se descongela.
    pub fn make_immortal_logged(this: &Self, log: &mut FreezeLog) {
        log.freeze(this.header());
    }

    /// ¿Inmortal con alcance (`make_immortal_logged`)? Se va a descongelar: no se puede compartir
    /// más allá de ese alcance.
    #[inline]
    pub fn is_scoped(this: &Self) -> bool {
        scoped_h(this.header())
    }

    /// ¿Inmortal para siempre (`make_immortal`)? No el de alcance ni el de cuenta llena (que sigue
    /// siendo de un solo hilo).
    #[inline]
    pub fn is_permanent(this: &Self) -> bool {
        permanent_h(this.header())
    }

    /// Cuántos `Shared` lo tienen. `usize::MAX` si es inmortal (siempre "compartido").
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

    #[inline]
    pub fn try_borrow(&self) -> Result<Ref<'_, T>, BorrowError> {
        let h = self.header();
        let counted = take_read(h)?;
        // SAFETY: no hay escritor (o es inmortal y nunca lo tiene); el valor está vivo.
        let value = unsafe { NonNull::new_unchecked(self.ptr.as_ref().value.get()) };
        Ok(Ref { value, release: if counted { Some(&h.borrow) } else { None }, _life: PhantomData })
    }

    /// Prestado para escribir. Un inmortal no se escribe: pánico (nunca una carrera de datos).
    #[inline]
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        match self.try_borrow_mut() {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        }
    }

    #[inline]
    pub fn try_borrow_mut(&self) -> Result<RefMut<'_, T>, BorrowError> {
        let h = self.header();
        take_write(h)?;
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
        inc_weak(this.header());
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
        inc_strong(self.header());
        Shared { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T> Drop for Shared<T> {
    #[inline]
    fn drop(&mut self) {
        if dec_strong(self.header()) {
            // SAFETY: era el último dueño.
            unsafe { self.drop_slow() };
        }
    }
}

impl<T> Shared<T> {
    /// Ver `SharedTail::drop_slow`.
    ///
    /// # Safety
    /// strong acaba de llegar a 0.
    #[inline(never)]
    unsafe fn drop_slow(&mut self) {
        // El débil implícito de `Rc`: mientras se suelta el valor, su `Drop` puede soltar el último
        // débil a este mismo objeto (una forma suelta a su madre, que suelta el débil a la hija) y,
        // con strong = 0 y weak = 0, liberar la reserva a mitad del soltado (doble liberación).
        let h: *const Header = self.header();
        // SAFETY: la reserva está viva (recién bajó strong a 0 y nadie la libera sin este débil).
        unsafe { hold_weak(&*h) };
        // SAFETY: el valor se suelta una vez. Nadie lo tiene prestado (un préstamo vive menos que el
        // `Shared` del que salió).
        unsafe { std::ptr::drop_in_place(self.ptr.as_ref().value.get()) };
        // SAFETY: la reserva sigue viva gracias al débil implícito, que se devuelve acá.
        unsafe { (*h).weak.set((*h).weak.get() - 1) };
        // SAFETY: strong = 0 y el valor ya se soltó.
        unsafe { release_if_unreferenced(self.ptr) };
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
        upgrade_h(self.header()).then(|| Shared { ptr: self.ptr, _owns: PhantomData })
    }

    pub fn strong_count(&self) -> usize {
        strong_count_h(self.header())
    }
}

impl<T> Clone for WeakShared<T> {
    fn clone(&self) -> WeakShared<T> {
        inc_weak(self.header());
        WeakShared { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T> Drop for WeakShared<T> {
    fn drop(&mut self) {
        if dec_weak(self.header()) {
            // SAFETY: strong = 0 (el valor ya se soltó) y era el último débil.
            unsafe { release_if_unreferenced(self.ptr) };
        }
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
    /// La bandera de préstamo, para descontar al soltar; `None` si el objeto es inmortal (no se
    /// vuelve inmortal mientras alguien lo tiene prestado: ver `make_immortal`).
    release: Option<&'b Cell<i16>>,
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
        if let Some(b) = orig.release {
            let n = b.get();
            if n + 1 >= SCOPED_BORROW {
                panic!("{}", BorrowError::TooManyReaders);
            }
            b.set(n + 1);
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
        if let Some(b) = self.release {
            b.set(b.get() - 1);
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

/// Dónde empieza el objeto (constante por tipo).
#[inline(always)]
const fn tail_obj_off<T: ?Sized + TailObject>() -> usize {
    std::mem::size_of::<TailPrefix>().div_ceil(T::ALIGN) * T::ALIGN
}

/// Dónde empieza el objeto y la reserva entera, para `len` elementos.
fn tail_layout<T: ?Sized + TailObject>(len: usize) -> (usize, Layout) {
    let align = T::ALIGN.max(std::mem::align_of::<TailPrefix>());
    let obj_off = tail_obj_off::<T>();
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
        T::from_raw_parts(unsafe { self.ptr.as_ptr().cast::<u8>().add(tail_obj_off::<T>()) }, len)
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

    /// `make_immortal` anotando la cuenta que tenía en `log`, para devolvérsela con `FreezeLog::thaw`
    /// (R2.3: un congelado con alcance). Lo que ya era inmortal no se anota: no se descongela.
    pub fn make_immortal_logged(this: &Self, log: &mut FreezeLog) {
        log.freeze(this.header());
    }

    /// ¿Inmortal con alcance (`make_immortal_logged`)? Se va a descongelar: no se puede compartir
    /// más allá de ese alcance.
    #[inline]
    pub fn is_scoped(this: &Self) -> bool {
        scoped_h(this.header())
    }

    /// ¿Inmortal para siempre (`make_immortal`)? No el de alcance ni el de cuenta llena (que sigue
    /// siendo de un solo hilo).
    #[inline]
    pub fn is_permanent(this: &Self) -> bool {
        permanent_h(this.header())
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
        Ok(Ref { value, release: if counted { Some(&h.borrow) } else { None }, _life: PhantomData })
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
            // SAFETY: era el último dueño.
            unsafe { self.drop_slow() };
        }
    }
}

impl<T: ?Sized + TailObject> SharedTail<T> {
    /// El último dueño suelta el objeto y, si no quedan débiles, la reserva. Fuera de línea (como
    /// `Rc::drop_slow`): inlineado, engordaba el drop de todo valor que pueda tener un mapa.
    ///
    /// # Safety
    /// strong acaba de llegar a 0.
    #[inline(never)]
    unsafe fn drop_slow(&mut self) {
        // El débil implícito de `Rc`: mientras se suelta el valor, su `Drop` puede soltar el último
        // débil a este mismo objeto (una forma suelta a su madre, que suelta el débil a la hija) y,
        // con strong = 0 y weak = 0, liberar la reserva a mitad del soltado (doble liberación).
        let h: *const Header = self.header();
        // SAFETY: la reserva está viva (recién bajó strong a 0 y nadie la libera sin este débil).
        unsafe { hold_weak(&*h) };
        // SAFETY: el objeto se suelta una vez (nadie lo tiene prestado: un préstamo vive menos que el
        // `SharedTail` del que salió).
        unsafe { std::ptr::drop_in_place(self.obj_ptr()) };
        // SAFETY: la reserva sigue viva gracias al débil implícito, que se devuelve acá.
        unsafe { (*h).weak.set((*h).weak.get() - 1) };
        // SAFETY: el objeto ya se soltó.
        unsafe { Self::release_if_unreferenced(self.ptr) };
    }
}

impl<T: ?Sized + TailObject> WeakTail<T> {
    pub fn upgrade(&self) -> Option<SharedTail<T>> {
        // SAFETY: la reserva vive mientras haya un débil.
        let h = unsafe { &self.ptr.as_ref().h };
        upgrade_h(h).then(|| SharedTail { ptr: self.ptr, _owns: PhantomData })
    }

    pub fn strong_count(&self) -> usize {
        // SAFETY: la reserva vive mientras haya un débil.
        strong_count_h(unsafe { &self.ptr.as_ref().h })
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

// --- `Obj<T>`: objeto inmutable (el reemplazo de `Rc<T>`) ---

/// Un objeto del montón de sólo lectura: la cabecera común de 8 bytes y el valor, como `Rc<T>` (lo
/// lee `Deref`, sin bandera de préstamo). Se escribe sólo con un único dueño (`get_mut`,
/// `make_mut`, como `Rc`). Puede volverse inmortal (`make_immortal`): ya no escribe su cuenta.
pub struct Obj<T> {
    ptr: NonNull<Inner<T>>,
    _owns: PhantomData<Inner<T>>,
}

/// Una referencia débil a un `Obj` (como `rc::Weak`).
pub struct WeakObj<T> {
    ptr: NonNull<Inner<T>>,
    _owns: PhantomData<Inner<T>>,
}

impl<T> Obj<T> {
    pub fn new(value: T) -> Obj<T> {
        let b = Box::new(Inner {
            h: Header { strong: Cell::new(1), weak: Cell::new(0), borrow: Cell::new(0) },
            value: UnsafeCell::new(value),
        });
        Obj { ptr: NonNull::from(Box::leak(b)), _owns: PhantomData }
    }

    #[inline]
    fn header(&self) -> &Header {
        // SAFETY: mientras haya un `Obj`, la reserva está viva (strong ≥ 1).
        unsafe { &self.ptr.as_ref().h }
    }

    #[inline]
    pub fn is_immortal(this: &Self) -> bool {
        this.header().strong.get() == IMMORTAL
    }

    /// Ver `Shared::make_immortal` (un `Obj` nunca está prestado: no falla). Idempotente.
    pub fn make_immortal(this: &Self) {
        make_immortal_h(this.header());
    }

    /// `make_immortal` anotando la cuenta que tenía en `log`, para devolvérsela con `FreezeLog::thaw`
    /// (R2.3: un congelado con alcance). Lo que ya era inmortal no se anota: no se descongela.
    pub fn make_immortal_logged(this: &Self, log: &mut FreezeLog) {
        log.freeze(this.header());
    }

    /// ¿Inmortal con alcance (`make_immortal_logged`)? Se va a descongelar: no se puede compartir
    /// más allá de ese alcance.
    #[inline]
    pub fn is_scoped(this: &Self) -> bool {
        scoped_h(this.header())
    }

    /// ¿Inmortal para siempre (`make_immortal`)? No el de alcance ni el de cuenta llena (que sigue
    /// siendo de un solo hilo).
    #[inline]
    pub fn is_permanent(this: &Self) -> bool {
        permanent_h(this.header())
    }

    /// `usize::MAX` si es inmortal.
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
        // SAFETY: la reserva está viva; sólo se calcula una dirección.
        unsafe { this.ptr.as_ref().value.get() }
    }

    /// `&mut` si es el único dueño, sin débiles y no es inmortal (como `Rc::get_mut`).
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        let h = this.header();
        if h.strong.get() == 1 && h.weak.get() == 0 {
            // SAFETY: único dueño y sin débiles: nadie más puede ver el valor.
            Some(unsafe { &mut *this.ptr.as_ref().value.get() })
        } else {
            None
        }
    }

    /// `&mut` copiando antes si no es el único dueño (como `Rc::make_mut`).
    pub fn make_mut(this: &mut Self) -> &mut T
    where
        T: Clone,
    {
        if Obj::get_mut(this).is_none() {
            *this = Obj::new((**this).clone());
        }
        Obj::get_mut(this).expect("recién copiado")
    }

    /// Saca el valor si es el único dueño (como `Rc::try_unwrap`).
    pub fn try_unwrap(this: Self) -> Result<T, Self> {
        if this.header().strong.get() != 1 {
            return Err(this);
        }
        this.header().strong.set(0);
        let ptr = this.ptr;
        std::mem::forget(this);
        // SAFETY: era el único dueño; el valor sale una vez (strong pasó a 0).
        let value = unsafe { std::ptr::read(ptr.as_ref().value.get()) };
        // SAFETY: strong = 0 y el valor ya salió.
        unsafe { release_if_unreferenced(ptr) };
        Ok(value)
    }

    /// El valor: sacado si es el único dueño, si no una copia (como `Rc::unwrap_or_clone`).
    pub fn unwrap_or_clone(this: Self) -> T
    where
        T: Clone,
    {
        Obj::try_unwrap(this).unwrap_or_else(|o| (*o).clone())
    }

    pub fn downgrade(this: &Self) -> WeakObj<T> {
        inc_weak(this.header());
        WeakObj { ptr: this.ptr, _owns: PhantomData }
    }

    /// Ver `SharedTail::drop_slow`.
    ///
    /// # Safety
    /// strong acaba de llegar a 0.
    #[inline(never)]
    unsafe fn drop_slow(&mut self) {
        // El débil implícito de `Rc`: mientras se suelta el valor, su `Drop` puede soltar el último
        // débil a este mismo objeto (una forma suelta a su madre, que suelta el débil a la hija) y,
        // con strong = 0 y weak = 0, liberar la reserva a mitad del soltado (doble liberación).
        let h: *const Header = self.header();
        // SAFETY: la reserva está viva (recién bajó strong a 0 y nadie la libera sin este débil).
        unsafe { hold_weak(&*h) };
        // SAFETY: el valor se suelta una vez (strong llegó a 0: nadie más lo ve).
        unsafe { std::ptr::drop_in_place(self.ptr.as_ref().value.get()) };
        // SAFETY: la reserva sigue viva gracias al débil implícito, que se devuelve acá.
        unsafe { (*h).weak.set((*h).weak.get() - 1) };
        // SAFETY: strong = 0 y el valor ya se soltó.
        unsafe { release_if_unreferenced(self.ptr) };
    }
}

impl<T> Deref for Obj<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: el valor vive mientras haya un `Obj`; sólo se escribe con un único dueño
        // (`get_mut`, que pide `&mut self`: no convive con este préstamo).
        unsafe { &*self.ptr.as_ref().value.get() }
    }
}

impl<T> Clone for Obj<T> {
    #[inline]
    fn clone(&self) -> Obj<T> {
        inc_strong(self.header());
        Obj { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T> Drop for Obj<T> {
    #[inline]
    fn drop(&mut self) {
        if dec_strong(self.header()) {
            // SAFETY: era el último dueño.
            unsafe { self.drop_slow() };
        }
    }
}

impl<T> WeakObj<T> {
    #[inline]
    fn header(&self) -> &Header {
        // SAFETY: mientras haya un débil, la reserva está viva.
        unsafe { &self.ptr.as_ref().h }
    }

    pub fn upgrade(&self) -> Option<Obj<T>> {
        upgrade_h(self.header()).then(|| Obj { ptr: self.ptr, _owns: PhantomData })
    }

    pub fn strong_count(&self) -> usize {
        strong_count_h(self.header())
    }
}

impl<T> Clone for WeakObj<T> {
    fn clone(&self) -> WeakObj<T> {
        inc_weak(self.header());
        WeakObj { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<T> Drop for WeakObj<T> {
    fn drop(&mut self) {
        if dec_weak(self.header()) {
            // SAFETY: strong = 0 (el valor ya se soltó) y era el último débil.
            unsafe { release_if_unreferenced(self.ptr) };
        }
    }
}

impl<T> From<T> for Obj<T> {
    fn from(value: T) -> Obj<T> {
        Obj::new(value)
    }
}

impl<T: Default> Default for Obj<T> {
    fn default() -> Obj<T> {
        Obj::new(T::default())
    }
}

impl<T> AsRef<T> for Obj<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T> std::borrow::Borrow<T> for Obj<T> {
    fn borrow(&self) -> &T {
        self
    }
}

impl<T: fmt::Debug> fmt::Debug for Obj<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: fmt::Display> fmt::Display for Obj<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<T: PartialEq> PartialEq for Obj<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl<T: Eq> Eq for Obj<T> {}

impl<T: PartialOrd> PartialOrd for Obj<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}
impl<T: Ord> Ord for Obj<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (**self).cmp(&**other)
    }
}

impl<T: std::hash::Hash> std::hash::Hash for Obj<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

// --- `ObjSlice<E>`: lista inmutable con puntero fino (el reemplazo de `Rc<[E]>`) ---

/// Cabecera + largo, antes de los elementos de un `ObjSlice`.
#[repr(C, align(8))]
struct SlicePrefix {
    h: Header,
    len: usize,
}

/// Una lista de sólo lectura de elementos `Copy` (bytes) con puntero FINO: el largo vive en el
/// objeto (`Rc<[u8]>` es gordo: 16 B). Ver `Obj` (cuenta, inmortal).
pub struct ObjSlice<E: Copy> {
    ptr: NonNull<SlicePrefix>,
    _owns: PhantomData<E>,
}

impl<E: Copy> ObjSlice<E> {
    const OFF: usize = {
        assert!(std::mem::align_of::<E>() <= std::mem::align_of::<SlicePrefix>(), "ObjSlice: element alignment above 8");
        std::mem::size_of::<SlicePrefix>()
    };

    fn layout(len: usize) -> Layout {
        let bytes = std::mem::size_of::<E>().checked_mul(len).and_then(|b| b.checked_add(Self::OFF)).expect("slice object too large");
        Layout::from_size_align(bytes, std::mem::align_of::<SlicePrefix>()).expect("slice object layout")
    }

    pub fn from_slice(items: &[E]) -> ObjSlice<E> {
        let layout = Self::layout(items.len());
        // SAFETY: el layout no es de tamaño cero (el prefijo ocupa 16 B).
        let p = unsafe { alloc::alloc(layout) };
        let Some(p) = NonNull::new(p) else { alloc::handle_alloc_error(layout) };
        // SAFETY: reserva nueva del tamaño del prefijo + los elementos, alineada a 8 (≥ la de `E`).
        unsafe {
            p.as_ptr().cast::<SlicePrefix>().write(SlicePrefix {
                h: Header { strong: Cell::new(1), weak: Cell::new(0), borrow: Cell::new(0) },
                len: items.len(),
            });
            std::ptr::copy_nonoverlapping(items.as_ptr(), p.as_ptr().add(Self::OFF).cast::<E>(), items.len());
        }
        ObjSlice { ptr: p.cast(), _owns: PhantomData }
    }

    #[inline]
    fn header(&self) -> &Header {
        // SAFETY: la reserva está viva mientras haya un `ObjSlice`.
        unsafe { &self.ptr.as_ref().h }
    }

    #[inline]
    pub fn is_immortal(this: &Self) -> bool {
        this.header().strong.get() == IMMORTAL
    }

    pub fn make_immortal(this: &Self) {
        make_immortal_h(this.header());
    }

    /// `make_immortal` anotando la cuenta que tenía en `log`, para devolvérsela con `FreezeLog::thaw`
    /// (R2.3: un congelado con alcance). Lo que ya era inmortal no se anota: no se descongela.
    pub fn make_immortal_logged(this: &Self, log: &mut FreezeLog) {
        log.freeze(this.header());
    }

    /// ¿Inmortal con alcance (`make_immortal_logged`)? Se va a descongelar: no se puede compartir
    /// más allá de ese alcance.
    #[inline]
    pub fn is_scoped(this: &Self) -> bool {
        scoped_h(this.header())
    }

    /// ¿Inmortal para siempre (`make_immortal`)? No el de alcance ni el de cuenta llena (que sigue
    /// siendo de un solo hilo).
    #[inline]
    pub fn is_permanent(this: &Self) -> bool {
        permanent_h(this.header())
    }

    #[inline]
    pub fn strong_count(this: &Self) -> usize {
        strong_count_h(this.header())
    }

    #[inline]
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.ptr == b.ptr
    }

    #[inline]
    pub fn as_ptr(this: &Self) -> *const E {
        // SAFETY: los elementos van justo después del prefijo, en la misma reserva.
        unsafe { this.ptr.as_ptr().cast::<u8>().add(Self::OFF).cast::<E>() }
    }

    /// Ver `Obj::drop_slow` (los elementos son `Copy`: sólo se devuelve la memoria).
    ///
    /// # Safety
    /// strong acaba de llegar a 0.
    #[inline(never)]
    unsafe fn drop_slow(&mut self) {
        // SAFETY: la reserva sigue viva; sin débiles (este tipo no los da), se devuelve.
        let len = unsafe { self.ptr.as_ref().len };
        // SAFETY: se reservó con este mismo layout.
        unsafe { alloc::dealloc(self.ptr.as_ptr().cast(), Self::layout(len)) };
    }
}

impl<E: Copy> Deref for ObjSlice<E> {
    type Target = [E];
    #[inline]
    fn deref(&self) -> &[E] {
        // SAFETY: `len` elementos inicializados después del prefijo; nunca se escriben.
        unsafe { std::slice::from_raw_parts(ObjSlice::as_ptr(self), self.ptr.as_ref().len) }
    }
}

impl<E: Copy> Clone for ObjSlice<E> {
    #[inline]
    fn clone(&self) -> ObjSlice<E> {
        inc_strong(self.header());
        ObjSlice { ptr: self.ptr, _owns: PhantomData }
    }
}

impl<E: Copy> Drop for ObjSlice<E> {
    #[inline]
    fn drop(&mut self) {
        if dec_strong(self.header()) {
            // SAFETY: era el último dueño.
            unsafe { self.drop_slow() };
        }
    }
}

impl<E: Copy> From<&[E]> for ObjSlice<E> {
    fn from(items: &[E]) -> ObjSlice<E> {
        ObjSlice::from_slice(items)
    }
}

impl<E: Copy> From<Vec<E>> for ObjSlice<E> {
    fn from(items: Vec<E>) -> ObjSlice<E> {
        ObjSlice::from_slice(&items)
    }
}

impl<E: Copy> From<Box<[E]>> for ObjSlice<E> {
    fn from(items: Box<[E]>) -> ObjSlice<E> {
        ObjSlice::from_slice(&items)
    }
}

impl<E: Copy, const N: usize> From<[E; N]> for ObjSlice<E> {
    fn from(items: [E; N]) -> ObjSlice<E> {
        ObjSlice::from_slice(&items)
    }
}

impl<E: Copy> FromIterator<E> for ObjSlice<E> {
    fn from_iter<I: IntoIterator<Item = E>>(it: I) -> ObjSlice<E> {
        ObjSlice::from_slice(&it.into_iter().collect::<Vec<E>>())
    }
}

impl<E: Copy> AsRef<[E]> for ObjSlice<E> {
    fn as_ref(&self) -> &[E] {
        self
    }
}

impl<E: Copy> std::borrow::Borrow<[E]> for ObjSlice<E> {
    fn borrow(&self) -> &[E] {
        self
    }
}

impl<E: Copy + fmt::Debug> fmt::Debug for ObjSlice<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<E: Copy + PartialEq> PartialEq for ObjSlice<E> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl<E: Copy + Eq> Eq for ObjSlice<E> {}

impl<E: Copy + std::hash::Hash> std::hash::Hash for ObjSlice<E> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

// --- operaciones de cabecera (de `Shared`, `SharedTail`, `Obj` y `ObjSlice`) ---
//
// Cada una tiene un camino rápido de UNA comparación, como `Rc`/`RefCell`, y un camino lento aparte
// (`#[cold]`) donde caen el inmortal, el desborde y los errores. Así el inmortal no cuesta nada en
// el camino normal (medido por instrucciones en la VM: R1.3a).

/// Una comparación y sin llamadas: una llamada (aunque sea al camino raro) obligaría a armar marco de
/// pila en cada clon de un valor (`SynValue::clone`), medido: ~10 instrucciones más por clon en la VM.
/// Si la cuenta llega al tope, el objeto queda **inmortal por cuenta llena**: no se libera nunca (una
/// fuga, nunca un uso después de liberar; hacen falta 4.000 millones de referencias al mismo objeto).
/// Ese inmortal sigue siendo de un solo hilo: la región compartida (R2) sólo toma objetos de
/// `make_immortal`, que además fija la bandera de préstamo.
#[inline]
fn inc_strong(h: &Header) {
    let s = h.strong.get();
    if s != IMMORTAL {
        h.strong.set(s + 1);
    }
}
/// `true` si era el último dueño (y no es inmortal). El caso común (2 ≤ cuenta < inmortal) en UNA
/// comparación sin signo, como `Rc`; el último dueño y el inmortal, aparte.
#[inline]
fn dec_strong(h: &Header) -> bool {
    let s = h.strong.get();
    if s.wrapping_sub(2) < IMMORTAL - 2 {
        h.strong.set(s - 1);
        false
    } else if s == 1 {
        h.strong.set(0);
        true
    } else {
        false // inmortal
    }
}
/// El débil implícito de `drop_slow` (strong ya es 0: nunca inmortal).
fn hold_weak(h: &Header) {
    let w = h.weak.get();
    if w == u16::MAX {
        overflow();
    }
    h.weak.set(w + 1);
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
#[inline]
fn strong_count_h(h: &Header) -> usize {
    match h.strong.get() {
        IMMORTAL => usize::MAX,
        n => n as usize,
    }
}
/// Lo que un congelado con alcance (R2.3) volvió inmortal, con la cuenta que tenía cada uno, para
/// devolvérsela (`thaw`). Si no se descongela, todo queda inmortal (una fuga, nunca un error).
#[derive(Default)]
pub struct FreezeLog {
    frozen: Vec<(NonNull<Header>, u32)>,
}

impl FreezeLog {
    pub fn new() -> FreezeLog {
        FreezeLog::default()
    }

    /// Cuántos objetos volvió inmortales.
    pub fn len(&self) -> usize {
        self.frozen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frozen.is_empty()
    }

    fn freeze(&mut self, h: &Header) {
        let s = h.strong.get();
        if s == IMMORTAL {
            return;
        }
        assert!(h.borrow.get() == 0, "make_immortal: the value is borrowed");
        self.frozen.push((NonNull::from(h), s));
        h.strong.set(IMMORTAL);
        h.borrow.set(SCOPED_BORROW);
    }

    /// Les devuelve a todos la cuenta que tenían y la bandera de préstamo libre: vuelven a ser
    /// objetos comunes del hilo que los congeló.
    ///
    /// # Safety
    /// Desde que se congelaron: (1) todo clon hecho de ellos ya se soltó (mientras eran inmortales,
    /// clonar y soltar no contaron, así que la cuenta anotada es la de los dueños que quedan); (2)
    /// ningún otro hilo los puede ver más (los que los leyeron terminaron y se esperaron, con sus
    /// `thread_local`); (3) los objetos siguen vivos (un inmortal no se libera, y los dueños
    /// anotados los sostienen).
    pub unsafe fn thaw(self) {
        for (h, s) in self.frozen {
            // SAFETY: (3) la reserva vive; (2) nadie más la lee mientras se escribe.
            let h = unsafe { h.as_ref() };
            h.strong.set(s);
            h.borrow.set(0);
        }
    }
}

fn permanent_h(h: &Header) -> bool {
    h.strong.get() == IMMORTAL && h.borrow.get() == IMMORTAL_BORROW
}

fn scoped_h(h: &Header) -> bool {
    h.strong.get() == IMMORTAL && h.borrow.get() == SCOPED_BORROW
}

fn make_immortal_h(h: &Header) {
    if h.strong.get() == IMMORTAL {
        return;
    }
    assert!(h.borrow.get() == 0, "make_immortal: the value is borrowed");
    h.strong.set(IMMORTAL);
    h.borrow.set(IMMORTAL_BORROW);
}
/// Toma un lector; `Ok(true)` si se cuenta (`Ok(false)`: inmortal, no se escribe nada).
#[inline]
fn take_read(h: &Header) -> Result<bool, BorrowError> {
    let b = h.borrow.get();
    // 0 ≤ b < tope, en una comparación sin signo (un escritor es -1: queda arriba). El tope deja
    // afuera las dos banderas de inmortal (`SCOPED_BORROW` e `IMMORTAL_BORROW`).
    if (b as u16) < (SCOPED_BORROW as u16) - 1 {
        h.borrow.set(b + 1);
        Ok(true)
    } else {
        take_read_slow(h, b)
    }
}
#[cold]
#[inline(never)]
fn take_read_slow(h: &Header, b: i16) -> Result<bool, BorrowError> {
    if h.strong.get() == IMMORTAL {
        Ok(false)
    } else if b < 0 {
        Err(BorrowError::Writing)
    } else {
        Err(BorrowError::TooManyReaders)
    }
}
#[inline]
fn take_write(h: &Header) -> Result<(), BorrowError> {
    if h.borrow.get() == 0 {
        h.borrow.set(-1);
        Ok(())
    } else {
        Err(take_write_slow(h))
    }
}
#[cold]
#[inline(never)]
fn take_write_slow(h: &Header) -> BorrowError {
    if h.strong.get() == IMMORTAL {
        BorrowError::Immortal
    } else if h.borrow.get() < 0 {
        BorrowError::Writing
    } else {
        BorrowError::Reading
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn obj_counts_drops_once_and_copies_on_write() {
        let n = Rc::new(Cell::new(0));
        let a = Obj::new(Probe(n.clone()));
        let b = a.clone();
        assert_eq!(Obj::strong_count(&a), 2);
        assert!(Obj::ptr_eq(&a, &b));
        drop(a);
        assert_eq!(n.get(), 0);
        drop(b);
        assert_eq!(n.get(), 1);

        let mut x = Obj::new(vec![1, 2]);
        let y = x.clone();
        Obj::make_mut(&mut x).push(3);
        assert_eq!(*x, vec![1, 2, 3]);
        assert_eq!(*y, vec![1, 2]);
        assert!(!Obj::ptr_eq(&x, &y));
        assert_eq!(Obj::try_unwrap(y), Ok(vec![1, 2]));
    }

    #[test]
    fn obj_immortal_is_never_freed_nor_written() {
        let n = Rc::new(Cell::new(0));
        let mut a = Obj::new(Probe(n.clone()));
        Obj::make_immortal(&a);
        assert!(Obj::is_immortal(&a));
        assert_eq!(Obj::strong_count(&a), usize::MAX);
        assert!(Obj::get_mut(&mut a).is_none());
        let ptr = a.ptr;
        let b = a.clone();
        drop(a);
        drop(b);
        assert_eq!(n.get(), 0, "un inmortal no se suelta");
        let mut v = Obj::new(1);
        Obj::make_immortal(&v);
        let vptr = v.ptr;
        let before = Obj::as_ptr(&v);
        *Obj::make_mut(&mut v) += 1; // copia: el inmortal no se escribe
        assert_eq!(*v, 2);
        assert_ne!(Obj::as_ptr(&v), before);
        // El test devuelve la memoria de los inmortales a mano (en el motor viven lo que el proceso).
        // SAFETY (del test): las reservas siguen vivas y nadie más las usa.
        unsafe {
            std::ptr::drop_in_place(ptr.as_ref().value.get());
            alloc::dealloc(ptr.as_ptr().cast(), Layout::new::<Inner<Probe>>());
            alloc::dealloc(vptr.as_ptr().cast(), Layout::new::<Inner<i32>>());
        }
        assert_eq!(n.get(), 1);
    }

    /// La doble liberación que encontró la puerta de R1.3c (`words`, formas de mapas): soltar la
    /// hija suelta a la madre, que suelta el último débil a la hija mientras la hija se suelta.
    #[test]
    fn dropping_a_child_that_frees_the_last_weak_to_itself() {
        struct Node {
            _parent: Option<Obj<Node>>,
            children: std::cell::RefCell<Vec<WeakObj<Node>>>,
        }
        let parent = Obj::new(Node { _parent: None, children: Default::default() });
        let child = Obj::new(Node { _parent: Some(parent.clone()), children: Default::default() });
        parent.children.borrow_mut().push(Obj::downgrade(&child));
        drop(parent);
        drop(child);

        struct SNode {
            _parent: Option<Shared<SNode>>,
            children: Vec<WeakShared<SNode>>,
        }
        let parent = Shared::new(SNode { _parent: None, children: Vec::new() });
        let child = Shared::new(SNode { _parent: Some(parent.clone()), children: Vec::new() });
        parent.borrow_mut().children.push(Shared::downgrade(&child));
        drop(parent);
        drop(child);
    }

    #[test]
    fn a_scoped_freeze_gives_the_counts_back() {
        let n = Rc::new(Cell::new(0));
        let a = Shared::new(Probe(n.clone()));
        let a2 = a.clone();
        let o = Obj::new(7);
        let already = Obj::new(1);
        Obj::make_immortal(&already);
        let mut log = FreezeLog::new();
        Shared::make_immortal_logged(&a, &mut log);
        Obj::make_immortal_logged(&o, &mut log);
        Obj::make_immortal_logged(&already, &mut log);
        assert_eq!(log.len(), 2, "lo ya inmortal no se anota");
        assert!(Shared::is_scoped(&a) && Obj::is_scoped(&o) && !Obj::is_scoped(&already));
        assert!(!Shared::is_permanent(&a) && Obj::is_permanent(&already));
        assert_eq!(Shared::strong_count(&a), usize::MAX);
        {
            // Mientras está congelado: clonar y soltar no cuentan, leer no toma préstamo.
            let c = a.clone();
            let _r = c.borrow();
            assert!(a.try_borrow_mut().is_err());
        }
        // SAFETY (del test): los clones de la ventana ya se soltaron; un solo hilo.
        unsafe { log.thaw() };
        assert_eq!(Shared::strong_count(&a), 2);
        assert_eq!(Obj::strong_count(&o), 1);
        assert!(Obj::is_immortal(&already));
        a.borrow_mut().0.set(0);
        drop(a);
        assert_eq!(n.get(), 0);
        drop(a2);
        assert_eq!(n.get(), 1, "descongelado se suelta una vez, como siempre");
        // El inmortal de antes no se descongeló: el test devuelve su memoria a mano.
        let p = already.ptr;
        drop(already);
        // SAFETY (del test): la reserva sigue (inmortal) y nadie más la usa.
        unsafe { alloc::dealloc(p.as_ptr().cast(), Layout::new::<Inner<i32>>()) };
    }

    #[test]
    fn obj_weak_upgrades_while_alive() {
        let a = Obj::new(String::from("x"));
        let w = Obj::downgrade(&a);
        assert_eq!(w.upgrade().as_deref().map(String::as_str), Some("x"));
        drop(a);
        assert!(w.upgrade().is_none());
        let w2 = w.clone();
        drop(w);
        assert!(w2.upgrade().is_none());
    }

    #[test]
    fn obj_slice_thin_and_counted() {
        assert_eq!(std::mem::size_of::<ObjSlice<u8>>(), std::mem::size_of::<usize>());
        assert_eq!(std::mem::size_of::<Option<ObjSlice<u8>>>(), std::mem::size_of::<usize>());
        let a: ObjSlice<u8> = ObjSlice::from(&b"hola"[..]);
        let b = a.clone();
        assert_eq!(&*b, b"hola");
        assert_eq!(ObjSlice::strong_count(&a), 2);
        assert_eq!(a, ObjSlice::from(vec![b'h', b'o', b'l', b'a']));
        drop(a);
        assert_eq!(b.len(), 4);
        let e: ObjSlice<u8> = ObjSlice::from(Vec::new());
        assert!(e.is_empty());
        ObjSlice::make_immortal(&e);
        assert!(ObjSlice::is_immortal(&e));
        let eptr = e.ptr;
        let e2 = e.clone();
        drop(e);
        drop(e2);
        // SAFETY (del test): el inmortal no se liberó; se devuelve a mano.
        unsafe { alloc::dealloc(eptr.as_ptr().cast(), ObjSlice::<u8>::layout(0)) };
        let w: ObjSlice<u64> = (0..5u64).collect();
        assert_eq!(&*w, &[0, 1, 2, 3, 4]);
        assert_eq!(ObjSlice::as_ptr(&w) as usize % 8, 0);
    }

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
        assert_eq!(read(&a), (IMMORTAL, IMMORTAL_BORROW));
        {
            let _r1 = a.borrow();
            let _r2 = c.borrow();
            let _r3 = Ref::clone(&_r1);
            assert_eq!(read(&a), (IMMORTAL, IMMORTAL_BORROW));
        }
        assert_eq!(read(&a), (IMMORTAL, IMMORTAL_BORROW));
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
    #[should_panic(expected = "the value is borrowed")]
    fn cannot_make_immortal_while_read() {
        let a = Shared::new(5u32);
        let _r = a.borrow();
        Shared::make_immortal(&a);
    }

    #[test]
    #[should_panic(expected = "the value is borrowed")]
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

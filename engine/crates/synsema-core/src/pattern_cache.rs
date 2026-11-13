//! Caché de patrones de regex ya compilados (v0.6.60).
//!
//! Un patrón de Synsema es un texto: no hay un valor «regex compilada» que el programa guarde,
//! como en Rust o en Go. Hasta v0.6.59 eso costaba una compilación por llamada (medido:
//! `regex_find_all(t, "\\w+")`, 0,46 ms cada vez). El motor guarda los compilados, como hace el
//! módulo `re` de Python.
//!
//! La misma política para las dos familias (`regex_*` en este crate, `backtrack_*` en la stdlib):
//! por hilo, [`PATTERN_CACHE_ENTRIES`] entradas, sale la que hace más que no se usa, y un patrón
//! de más de [`PATTERN_CACHE_MAX_PATTERN`] bytes no se guarda. Un patrón que no compila tampoco:
//! el error se vuelve a producir en cada llamada.
//!
//! **La clave es `(patrón como lo escribió el programa, variante)`.** La variante dice qué se
//! compiló con ese texto: [`AS_WRITTEN`] (el patrón tal cual) o [`FULL_MATCH`] (el que cubre todo
//! el texto: `matches` lo envuelve con [`build_full_match`]; `backtrack_matches` se lo pide a su
//! motor, que lo arma sobre el árbol del patrón). El texto envuelto nunca es la clave: si lo
//! fuera, el compilado de `matches(t, "a)(b")` sería el mismo que el de un programa que escribió
//! `^(?:a)(b)$` a mano, y el segundo le salteaba la validación al primero.
//!
//! **Cuánto vive.** Lo que guarda un hilo es de una unidad de trabajo: [`clear_thread_caches`] lo
//! suelta todo, y `Interpreter::reset_for_request` lo llama. En `serve` (y en un guest de wasm que
//! atiende requests) eso es al terminar cada request, tick de cron o handler de socket: una
//! request no retiene memoria en el worker ni le deja a la siguiente un compilado cuyo tiempo se
//! pueda medir. En `run` es la corrida entera.
//!
//! **Cuánto ocupa.** Los dos techos miden el texto del patrón, no el compilado, y el tamaño del
//! compilado no depende del largo del texto: `\w{209}` son 7 bytes de patrón y 11 MB de compilado
//! (la crate `regex` corta en 10 MB de NFA; las `backtrack_*`, en 16 MiB por compilado: su
//! `MAX_COMPILED_BYTES`). Un hilo puede retener 32 de esos por familia mientras dura su unidad de
//! trabajo.
//!
//! Con el compilado va su caché de búsqueda (lo que el motor arma para buscar: los estados del
//! DFA perezoso, la tabla de la PikeVM), que no es del compilado sino de quien busca y puede ser
//! mucho más grande que él: 36 MB para un patrón de 60 grupos. Las dos familias la tienen aparte
//! del compilado y la miden al terminar cada llamada: una de más de [`KEPT_SEARCH_CACHE_BYTES`] se
//! suelta (ronda 4 de la auditoría, A-2). Entre llamadas un patrón guardado retiene entonces su
//! compilado y a lo sumo eso de caché.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// La variante de un patrón compilado tal como está escrito.
pub const AS_WRITTEN: u32 = 0;
/// La variante de un patrón compilado para cubrir todo el texto.
pub const FULL_MATCH: u32 = 1;

/// Cuántos compilados guarda cada hilo.
pub const PATTERN_CACHE_ENTRIES: usize = 32;
/// Un patrón más largo que esto (en bytes) se compila en cada llamada y no ocupa lugar.
pub const PATTERN_CACHE_MAX_PATTERN: usize = 8 * 1024;
/// Lo más que ocupa la caché de búsqueda de un patrón cuando su llamada terminó, en bytes: una
/// que quedó con más se suelta, y la llamada siguiente arma otra. Es lo que retiene entre
/// llamadas, además del compilado, cada patrón de la caché del hilo, en las dos familias
/// (`linear_regex.rs` acá; `Regex::trim_search_caches` del fork de `fancy-regex` para las
/// `backtrack_*`). Lo que se mide es lo que el motor dice que tiene su caché; el proceso retiene
/// hasta el doble de eso (la capacidad de sobra de sus tablas).
///
/// Medido: los patrones de tokenizador usan 0,1 MB, así que quedan como están para la llamada
/// siguiente; la caché de un DFA perezoso tiene su propio techo de 2 MiB. Lo que pasa de acá es
/// la tabla de la PikeVM de un patrón con decenas de grupos, o las cachés de varios tramos que
/// llenaron cada uno su DFA.
pub const KEPT_SEARCH_CACHE_BYTES: usize = 2 << 20;

/// Las entradas van de la menos usada (adelante) a la más reciente (al final).
pub struct PatternCache<T> {
    entries: Vec<(Box<str>, u32, T)>,
}

impl<T: Clone> PatternCache<T> {
    pub const fn new() -> Self {
        PatternCache { entries: Vec::new() }
    }

    /// El compilado de `(pattern, variant)`: el guardado, o el que arma `build` (que se guarda si
    /// salió bien y el patrón entra).
    pub fn get_or_try_insert<E>(
        &mut self,
        pattern: &str,
        variant: u32,
        build: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        if let Some(i) = self.entries.iter().position(|(p, v, _)| *v == variant && &**p == pattern) {
            let last = self.entries.len() - 1;
            if i != last {
                let e = self.entries.remove(i);
                self.entries.push(e);
            }
            return Ok(self.entries[last].2.clone());
        }
        let built = build()?;
        if pattern.len() <= PATTERN_CACHE_MAX_PATTERN {
            if self.entries.len() >= PATTERN_CACHE_ENTRIES {
                self.entries.remove(0);
            }
            self.entries.push((pattern.into(), variant, built.clone()));
        }
        Ok(built)
    }

    /// Suelta todos los compilados, y la memoria de la lista. Devuelve cuántos había.
    pub fn clear(&mut self) -> usize {
        std::mem::take(&mut self.entries).len()
    }

    /// Los compilados guardados, del que hace más que no se usa al más reciente.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, _, compiled)| compiled)
    }

    /// Cuántos compilados hay guardados.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<T: Clone> Default for PatternCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    /// Cómo se vacía cada caché de patrones de este hilo.
    static CLEANERS: RefCell<Vec<fn() -> usize>> = const { RefCell::new(Vec::new()) };
}

/// Cuántos compilados soltó [`clear_thread_caches`] en todo el proceso.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Anota cómo se vacía una caché de patrones de este hilo (`clear` devuelve cuántos compilados
/// soltó). Lo llama el inicializador del `thread_local` de cada caché (una vez por hilo, la
/// primera vez que se usa): así [`clear_thread_caches`] alcanza también a las cachés de otros
/// crates (la de `backtrack_*` está en la stdlib, que core no conoce).
pub fn register_cleaner(clear: fn() -> usize) {
    CLEANERS.with(|c| c.borrow_mut().push(clear));
}

/// Vacía todas las cachés de patrones de este hilo. Es el fin de una unidad de trabajo: lo llama
/// `Interpreter::reset_for_request`. Devuelve cuántos compilados soltó.
pub fn clear_thread_caches() -> usize {
    // La lista se copia: un limpiador no corre con `CLEANERS` prestada.
    let cleaners: Vec<fn() -> usize> = CLEANERS.with(|c| c.borrow().clone());
    let dropped: usize = cleaners.into_iter().map(|clear| clear()).sum();
    if dropped > 0 {
        DROPPED.fetch_add(dropped as u64, Ordering::Relaxed);
    }
    dropped
}

/// Cuántos compilados soltaron las llamadas a [`clear_thread_caches`] de todos los hilos del
/// proceso desde que arrancó. Es para medir desde afuera de un hilo que la limpieza corre (un
/// worker de `serve` no se puede mirar por dentro): los tests de `serve` lo usan.
pub fn dropped_total() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Por qué no hay compilado de [`build_full_match`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FullMatchError<E> {
    /// El patrón, tal como está escrito, no compila.
    Pattern(E),
    /// El patrón compila, pero envuelto no (pasa de un límite de anidamiento o de tamaño por lo
    /// que agrega el envoltorio).
    Wrapped(E),
}

/// Cómo empieza el detalle de un [`FullMatchError::Wrapped`] en el error del programa.
pub const FULL_MATCH_DOES_NOT_FIT: &str =
    "the pattern is valid, but not once it is wrapped as ^(?:…)$ to cover the whole text: ";

/// El compilado de «`pattern` cubre todo el texto» para un motor que no sabe hacerlo solo, con
/// `build` como compilador: lo usa `matches` con la crate `regex`. (`backtrack_matches` no: su
/// motor tiene subrutinas, y envuelto el texto `\g<0>` llamaría también a las anclas.)
///
/// 1. El patrón se compila tal como está escrito. Envuelto, uno desbalanceado puede compilar
///    (`a)(b` → `^(?:a)(b)$`), y el error de uno inválido hablaría de un texto que el programa no
///    escribió.
/// 2. Se compila `^(?:pattern)$`.
/// 3. Si eso falla y el patrón tiene un `#`, se compila `^(?:pattern` + salto de línea + `)$`. En
///    modo verboso (`(?x)`) un `#` abre un comentario hasta el fin de la línea, y un patrón que
///    termina en comentario se come el cierre del envoltorio. El salto de línea termina el
///    comentario, y en modo verboso no significa nada. Fuera del modo verboso el salto sería un
///    carácter más del patrón, pero ahí el paso 2 no falla por un `#`: lo único que un salto de
///    línea cierra es un comentario, así que si el paso 2 falló por otra cosa (un límite), el 3
///    falla igual.
pub fn build_full_match<T, E>(
    pattern: &str,
    build: impl Fn(&str) -> Result<T, E>,
) -> Result<T, FullMatchError<E>> {
    build(pattern).map_err(FullMatchError::Pattern)?;
    match build(&format!("^(?:{})$", pattern)) {
        Ok(compiled) => Ok(compiled),
        Err(wrapped) => {
            if pattern.contains('#') {
                if let Ok(compiled) = build(&format!("^(?:{}\n)$", pattern)) {
                    return Ok(compiled);
                }
            }
            Err(FullMatchError::Wrapped(wrapped))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Compila «el patrón» como su propio texto con la variante, y cuenta las compilaciones.
    fn get(c: &mut PatternCache<String>, builds: &Cell<u32>, pattern: &str, variant: u32) -> String {
        c.get_or_try_insert::<()>(pattern, variant, || {
            builds.set(builds.get() + 1);
            Ok(format!("{}#{}", pattern, variant))
        })
        .unwrap()
    }

    #[test]
    fn a_pattern_is_built_once_and_each_key_gets_its_own_value() {
        let (mut c, n) = (PatternCache::new(), Cell::new(0));
        assert_eq!(get(&mut c, &n, "a", 0), "a#0");
        assert_eq!(get(&mut c, &n, "a", 0), "a#0");
        assert_eq!(n.get(), 1);
        // otro patrón y otra variante del mismo patrón son otras entradas
        assert_eq!(get(&mut c, &n, "b", 0), "b#0");
        assert_eq!(get(&mut c, &n, "a", 1), "a#1");
        assert_eq!(get(&mut c, &n, "a", 0), "a#0");
        assert_eq!(get(&mut c, &n, "b", 0), "b#0");
        assert_eq!((n.get(), c.len()), (3, 3));
    }

    #[test]
    fn the_least_recently_used_entry_leaves_first() {
        let (mut c, n) = (PatternCache::new(), Cell::new(0));
        for i in 0..PATTERN_CACHE_ENTRIES {
            get(&mut c, &n, &format!("p{}", i), 0);
        }
        // `p0` se usa: deja de ser la más vieja. La que entra saca a `p1`.
        get(&mut c, &n, "p0", 0);
        get(&mut c, &n, "nuevo", 0);
        assert_eq!(c.len(), PATTERN_CACHE_ENTRIES);
        let before = n.get();
        get(&mut c, &n, "p0", 0);
        assert_eq!(n.get(), before, "p0 seguía guardado");
        get(&mut c, &n, "p1", 0);
        assert_eq!(n.get(), before + 1, "p1 había salido");
    }

    #[test]
    fn many_patterns_in_rounds_always_give_their_own_value() {
        let (mut c, n) = (PatternCache::new(), Cell::new(0));
        for _ in 0..3 {
            for i in 0..(PATTERN_CACHE_ENTRIES + 8) {
                let p = format!("p{}", i);
                assert_eq!(get(&mut c, &n, &p, 0), format!("{}#0", p));
            }
        }
        assert_eq!(c.len(), PATTERN_CACHE_ENTRIES);
    }

    #[test]
    fn an_error_is_not_kept_and_a_long_pattern_is_not_stored() {
        let mut c: PatternCache<String> = PatternCache::new();
        let n = Cell::new(0);
        for _ in 0..2 {
            let r = c.get_or_try_insert("malo", 0, || {
                n.set(n.get() + 1);
                Err::<String, &str>("no compila")
            });
            assert_eq!(r, Err("no compila"));
        }
        assert_eq!((n.get(), c.len()), (2, 0));

        let long = "x".repeat(PATTERN_CACHE_MAX_PATTERN + 1);
        let m = Cell::new(0);
        assert_eq!(get(&mut c, &m, &long, 0), format!("{}#0", long));
        assert_eq!(get(&mut c, &m, &long, 0), format!("{}#0", long));
        assert_eq!((m.get(), c.len()), (2, 0));
        let fits = "x".repeat(PATTERN_CACHE_MAX_PATTERN);
        get(&mut c, &m, &fits, 0);
        get(&mut c, &m, &fits, 0);
        assert_eq!((m.get(), c.len()), (3, 1));
    }

    #[test]
    fn clear_drops_every_entry() {
        let (mut c, n) = (PatternCache::new(), Cell::new(0));
        get(&mut c, &n, "a", AS_WRITTEN);
        get(&mut c, &n, "a", FULL_MATCH);
        assert_eq!((n.get(), c.len()), (2, 2));
        assert_eq!(c.clear(), 2);
        assert!(c.is_empty());
        assert_eq!(c.clear(), 0);
        get(&mut c, &n, "a", AS_WRITTEN);
        assert_eq!((n.get(), c.len()), (3, 1), "después de vaciar se vuelve a compilar");
    }

    thread_local! {
        static A: RefCell<PatternCache<String>> = {
            register_cleaner(|| A.with(|c| c.borrow_mut().clear()));
            RefCell::new(PatternCache::new())
        };
        static B: RefCell<PatternCache<String>> = {
            register_cleaner(|| B.with(|c| c.borrow_mut().clear()));
            RefCell::new(PatternCache::new())
        };
    }

    /// Cada caché se anota al usarse por primera vez en el hilo, y `clear_thread_caches` las
    /// vacía a todas. En un hilo propio: las cachés y la lista son del hilo.
    #[test]
    fn clearing_the_thread_reaches_every_registered_cache() {
        std::thread::spawn(|| {
            // sin ninguna caché usada no hay nada que vaciar, y no es un error
            assert_eq!(clear_thread_caches(), 0);
            let n = Cell::new(0);
            A.with(|c| get(&mut c.borrow_mut(), &n, "a", 0));
            B.with(|c| get(&mut c.borrow_mut(), &n, "b", 0));
            B.with(|c| get(&mut c.borrow_mut(), &n, "c", 0));
            assert_eq!((A.with(|c| c.borrow().len()), B.with(|c| c.borrow().len())), (1, 2));
            let before = dropped_total();
            assert_eq!(clear_thread_caches(), 3);
            // el total del proceso sube por lo menos eso (otros hilos pueden sumar)
            assert!(dropped_total() >= before + 3);
            assert_eq!((A.with(|c| c.borrow().len()), B.with(|c| c.borrow().len())), (0, 0));
            // y siguen andando, anotadas una sola vez
            A.with(|c| get(&mut c.borrow_mut(), &n, "a", 0));
            assert_eq!(n.get(), 4);
            assert_eq!(CLEANERS.with(|c| c.borrow().len()), 2);
            assert_eq!(clear_thread_caches(), 1);
            assert_eq!(A.with(|c| c.borrow().len()), 0);
        })
        .join()
        .unwrap();
    }

    /// «Compilar» para estos tests: el texto tiene que tener los paréntesis balanceados, y un `#`
    /// abre un comentario hasta el salto de línea (como el modo verboso). Más de `limit` bytes no
    /// entra.
    fn toy(limit: usize) -> impl Fn(&str) -> Result<String, String> {
        move |p: &str| {
            if p.len() > limit {
                return Err(format!("demasiado grande: {}", p.len()));
            }
            let (mut depth, mut comment) = (0i32, false);
            for ch in p.chars() {
                match ch {
                    '\n' => comment = false,
                    _ if comment => {}
                    '#' => comment = true,
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth < 0 {
                            return Err("cierra sin abrir".to_string());
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                return Err("abre sin cerrar".to_string());
            }
            Ok(p.to_string())
        }
    }

    #[test]
    fn the_full_match_is_built_from_the_pattern_as_written() {
        let build = toy(100);
        assert_eq!(build_full_match("a|b", &build), Ok("^(?:a|b)$".to_string()));
        // desbalanceado: envuelto compilaría, y es un error del patrón escrito
        assert_eq!(build("^(?:a)(b)$"), Ok("^(?:a)(b)$".to_string()));
        assert_eq!(build_full_match("a)(b", &build), Err(FullMatchError::Pattern("cierra sin abrir".to_string())));
        // termina en comentario: el envoltorio lleva el salto de línea
        assert_eq!(build_full_match("a # c", &build), Ok("^(?:a # c\n)$".to_string()));
        // con el salto ya puesto no hace falta agregarlo
        assert_eq!(build_full_match("a # c\n", &build), Ok("^(?:a # c\n)$".to_string()));
        // válido, pero envuelto no entra: el error es el del envuelto, y lo dice su variante
        let exact = "x".repeat(100);
        assert_eq!(build(&exact), Ok(exact.clone()));
        assert_eq!(build_full_match(&exact, &build), Err(FullMatchError::Wrapped("demasiado grande: 106".to_string())));
        // lo mismo con un `#` adentro: el respaldo con el salto tampoco entra, y el error es el primero
        let exact = format!("{}#", "x".repeat(99));
        assert_eq!(build_full_match(&exact, &build), Err(FullMatchError::Wrapped("demasiado grande: 106".to_string())));
    }
}

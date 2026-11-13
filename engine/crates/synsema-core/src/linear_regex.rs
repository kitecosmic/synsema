//! El motor de las `regex_*` (`matches`, `regex_find_all`, `regex_capture`, `capture`,
//! `regex_replace`): el de la crate `regex`, con la caché de búsqueda aparte del compilado
//! (v0.6.60).
//!
//! **Por qué no `regex::Regex`.** Un `regex::Regex` guarda adentro sus cachés de búsqueda (los
//! estados del DFA perezoso, la tabla de la PikeVM), en un `Pool` que nadie de afuera puede medir
//! ni vaciar. Mientras se compilaba en cada llamada (hasta v0.6.59) eso no importaba: la caché se
//! iba con el compilado. Con el compilado guardado en la caché de patrones del hilo
//! (`pattern_cache.rs`) quedaba retenida con él, y no es chica: la tabla de la PikeVM mide
//! estados del NFA × lugares de captura × 16 bytes, 36 MB para un patrón de 60 grupos `(\w)` y
//! 355 MB para uno de 190 (auditoría de v0.6.60, ronda 4, A-2). Treinta y dos patrones por hilo.
//!
//! La crate `regex` es una fachada de `regex_automata::meta::Regex`, y su documentación manda ahí
//! a quien necesite manejar la caché: `meta::Regex` busca con una `Cache` que le pasa el que
//! llama (`search_with`), y la `Cache` dice cuánto ocupa (`memory_usage`). Este módulo arma el
//! `meta::Regex` con la misma configuración que `regex::Regex::new` (los mismos límites, la misma
//! sintaxis, UTF-8), así que un patrón significa lo mismo, compila o falla igual y da el mismo
//! mensaje de error; lo fija `the_same_as_the_regex_crate`.
//!
//! **La regla de la caché.** Cada compilado tiene a lo sumo una caché de búsqueda, que usan todas
//! las búsquedas de una llamada. Al terminar la llamada se mide: si ocupa más que
//! [`KEPT_SEARCH_CACHE_BYTES`] se suelta, y la próxima llamada con ese patrón arma una nueva (lo
//! que pasaba en todas las llamadas hasta v0.6.59); si no, queda para la llamada siguiente, que
//! es lo que hace barato usar el mismo patrón en un bucle. Es la misma regla que tienen las
//! `backtrack_*` (`Regex::trim_search_caches` del fork de `fancy-regex`). Entre llamadas, un
//! patrón guardado retiene entonces su compilado y a lo sumo ese tanto de caché.
//!
//! Lo que una llamada usa mientras busca no cambia respecto de v0.6.59: es lo que pide el motor
//! lineal para ese patrón y ese texto.

use std::borrow::Cow;
use std::cell::Cell;

use regex_automata::meta::{Cache, Regex};
use regex_automata::util::iter::Searcher;
use regex_automata::util::syntax;
use regex_automata::{Input, MatchKind};

use crate::pattern_cache::KEPT_SEARCH_CACHE_BYTES;

/// Los dos límites con los que la crate `regex` arma su `meta::Regex` (`regex::RegexBuilder`:
/// `size_limit` y `dfa_size_limit` por defecto): el tamaño del NFA compilado y la capacidad de la
/// caché de cada DFA perezoso.
const NFA_SIZE_LIMIT: usize = 10 * (1 << 20);
const HYBRID_CACHE_CAPACITY: usize = 2 * (1 << 20);

/// Un patrón de `regex_*` compilado, con su caché de búsqueda.
///
/// No es `Sync` (la caché es de un hilo): vive en la caché de patrones del hilo.
pub struct LinearRegex {
    re: Regex,
    /// La caché de búsqueda que quedó de la última llamada, si entraba en lo que se retiene. Una
    /// búsqueda la saca de acá y la devuelve al terminar: si otra búsqueda con el mismo compilado
    /// empezara en el medio, armaría la suya.
    cache: Cell<Option<Cache>>,
}

impl LinearRegex {
    /// Compila `pattern` como `regex::Regex::new`. El error es el texto que daría esa crate.
    pub fn new(pattern: &str) -> Result<Self, String> {
        let config = Regex::config()
            .nfa_size_limit(Some(NFA_SIZE_LIMIT))
            .hybrid_cache_capacity(HYBRID_CACHE_CAPACITY)
            .match_kind(MatchKind::LeftmostFirst)
            .utf8_empty(true);
        let re = Regex::builder()
            .configure(config)
            .syntax(syntax::Config::new().utf8(true))
            .build(pattern)
            .map_err(|e| {
                // Como `regex::Error::from_meta_build_error` y su `Display`.
                if let Some(limit) = e.size_limit() {
                    format!("Compiled regex exceeds size limit of {} bytes.", limit)
                } else if let Some(syntax) = e.syntax_error() {
                    syntax.to_string()
                } else {
                    e.to_string()
                }
            })?;
        Ok(LinearRegex { re, cache: Cell::new(None) })
    }

    /// Las búsquedas de una llamada: `f` recibe el compilado y la caché. Al terminar, la caché
    /// queda guardada sólo si ocupa hasta [`KEPT_SEARCH_CACHE_BYTES`].
    fn search<R>(&self, f: impl FnOnce(&Regex, &mut Cache) -> R) -> R {
        let mut cache = self.cache.take().unwrap_or_else(|| self.re.create_cache());
        let out = f(&self.re, &mut cache);
        if cache.memory_usage() <= KEPT_SEARCH_CACHE_BYTES {
            self.cache.set(Some(cache));
        }
        out
    }

    /// Cuánto ocupa la caché de búsqueda que este compilado tiene guardada (0 si no tiene).
    pub fn kept_cache_bytes(&self) -> usize {
        let cache = self.cache.take();
        let bytes = cache.as_ref().map_or(0, Cache::memory_usage);
        self.cache.set(cache);
        bytes
    }

    /// Cuántos grupos tiene el patrón, contando el 0 (la coincidencia entera).
    pub fn captures_len(&self) -> usize {
        self.re.captures_len()
    }

    /// Si el patrón coincide en alguna parte del texto.
    pub fn is_match(&self, text: &str) -> bool {
        self.search(|re, cache| re.search_half_with(cache, &Input::new(text).earliest(true)).is_some())
    }

    /// Las coincidencias de izquierda a derecha, sin solaparse: `visit(comienzo, fin)`.
    pub fn for_each_match(&self, text: &str, mut visit: impl FnMut(usize, usize)) {
        self.search(|re, cache| {
            let mut searcher = Searcher::new(Input::new(text));
            while let Some(m) = searcher.advance(|input| Ok(re.search_with(cache, input))) {
                visit(m.start(), m.end());
            }
        })
    }

    /// El texto de cada coincidencia.
    pub fn find_all<'t>(&self, text: &'t str) -> Vec<&'t str> {
        let mut out = Vec::new();
        self.for_each_match(text, |start, end| out.push(&text[start..end]));
        out
    }

    /// Los grupos de la primera coincidencia: el 0 es la coincidencia entera, y uno que no
    /// participó es `None`. `None` si no hay coincidencia.
    pub fn captures<'t>(&self, text: &'t str) -> Option<Vec<Option<&'t str>>> {
        self.search(|re, cache| {
            let mut caps = re.create_captures();
            re.search_captures_with(cache, &Input::new(text), &mut caps);
            if !caps.is_match() {
                return None;
            }
            Some((0..caps.group_len()).map(|i| caps.get_group(i).map(|span| &text[span.start..span.end])).collect())
        })
    }

    /// El texto con cada coincidencia reemplazada por `template` (la sintaxis de la crate
    /// `regex`: `$1`, `${nombre}`, `$$`). Sin coincidencias, el mismo texto.
    pub fn replace_all<'t>(&self, text: &'t str, template: &str) -> Cow<'t, str> {
        let mut out: Option<String> = None;
        let mut last = 0usize;
        if !template.contains('$') {
            // Sin nada que expandir no hacen falta los grupos (la crate `regex` hace lo mismo).
            self.for_each_match(text, |start, end| {
                let new = out.get_or_insert_with(|| String::with_capacity(text.len()));
                new.push_str(&text[last..start]);
                new.push_str(template);
                last = end;
            });
        } else {
            self.search(|re, cache| {
                let mut caps = re.create_captures();
                let mut searcher = Searcher::new(Input::new(text));
                while let Some(m) = searcher.advance(|input| {
                    re.search_captures_with(cache, input, &mut caps);
                    Ok(caps.get_match())
                }) {
                    let new = out.get_or_insert_with(|| String::with_capacity(text.len()));
                    new.push_str(&text[last..m.start()]);
                    caps.interpolate_string_into(text, template, new);
                    last = m.end();
                }
            });
        }
        match out {
            None => Cow::Borrowed(text),
            Some(mut new) => {
                new.push_str(&text[last..]);
                Cow::Owned(new)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lo que la crate `regex` da para el mismo patrón y el mismo texto, en la forma de este
    /// módulo.
    fn reference_captures<'t>(re: &regex::Regex, text: &'t str) -> Option<Vec<Option<&'t str>>> {
        re.captures(text).map(|c| (0..c.len()).map(|i| c.get(i).map(|m| m.as_str())).collect())
    }

    /// El contrato del módulo: mismo resultado y mismo error que `regex::Regex`, que es lo que
    /// las `regex_*` usaban hasta v0.6.59.
    #[test]
    fn the_same_as_the_regex_crate() {
        let patterns = [
            r"\w+",
            r"",
            r"a*",
            r"\b",
            r"(a)|(b)",
            r"(?P<y>\d{4})-(?P<m>\d{2})",
            r"(\w)(\w)?",
            r"(?i)straße",
            r"\p{L}+|\p{N}+",
            r"^$",
            r"(?m)^\s*$",
            r"é|",
            r"(a|ab)(c|bcd)(d*)",
            r"[^\x00-\x7F]",
            r"x*?",
            r"(?s).",
            r"(?x) a b # dos letras",
        ];
        let texts = [
            "",
            "a",
            "ab abc",
            "abcd",
            "2026-11-12 y 1999-01-31",
            "STRASSE straße Straße",
            "ñandú 42 日本語 x",
            "a\n\n b\n",
            "aaa",
            "é",
            "\u{1F600}\u{1F600}",
        ];
        let templates = ["", "-", "<$0>", "$1$2", "${1}x", "$$", "$y/$m", "$9", "a$"];
        for p in patterns {
            let ours = LinearRegex::new(p).unwrap_or_else(|e| panic!("{:?} no compila: {}", p, e));
            let theirs = regex::Regex::new(p).unwrap();
            assert_eq!(ours.captures_len(), theirs.captures_len(), "{:?}", p);
            for t in texts {
                assert_eq!(ours.is_match(t), theirs.is_match(t), "is_match {:?} {:?}", p, t);
                let found: Vec<&str> = theirs.find_iter(t).map(|m| m.as_str()).collect();
                assert_eq!(ours.find_all(t), found, "find_all {:?} {:?}", p, t);
                assert_eq!(ours.captures(t), reference_captures(&theirs, t), "captures {:?} {:?}", p, t);
                for r in templates {
                    assert_eq!(ours.replace_all(t, r), theirs.replace_all(t, r), "replace {:?} {:?} {:?}", p, t, r);
                }
            }
        }
    }

    #[test]
    fn the_same_errors_as_the_regex_crate() {
        let big = format!("(?:{}){{400}}", r"\pL".repeat(40));
        let invalid = ["a)(b", "(a", "a{2,1}", "(?=a)", r"(a)\1", "[z-a]", r"\p{Nada}", "*", "(?P<n>a)(?P<n>b)", &big];
        for p in invalid {
            let ours = LinearRegex::new(p).err().unwrap_or_else(|| panic!("{:?} compila", p));
            let theirs = regex::Regex::new(p).unwrap_err().to_string();
            assert_eq!(ours, theirs, "{:?}", p);
        }
        // Las dos clases de error están en la lista: sintaxis y tamaño.
        assert!(LinearRegex::new(&big).err().unwrap().starts_with("Compiled regex exceeds size limit of 10485760"));
        assert!(LinearRegex::new("a)(b").err().unwrap().contains("unopened group"));
    }

    fn groups(n: usize) -> String {
        r"(\w)".repeat(n)
    }

    /// Ronda 4, A-2: lo que un compilado guardado retiene entre llamadas tiene techo. Un patrón
    /// de 60 grupos arma una tabla de la PikeVM de 36 MB para buscar; al terminar la llamada no
    /// queda. Uno chico conserva su caché para la llamada siguiente.
    #[test]
    fn a_search_cache_over_the_kept_size_does_not_outlive_its_call() {
        // Cuarenta palabras de cien letras: el patrón de 60 grupos coincide una vez en cada una.
        let text = format!("{} ", "a".repeat(100)).repeat(40);
        let big = LinearRegex::new(&groups(60)).unwrap();
        assert_eq!(big.kept_cache_bytes(), 0, "sin buscar no hay caché");
        // Cuánto necesita buscar con este patrón: se mide con una caché suelta.
        let mut loose = big.re.create_cache();
        let mut caps = big.re.create_captures();
        big.re.search_captures_with(&mut loose, &Input::new(&text), &mut caps);
        assert!(caps.is_match());
        assert!(loose.memory_usage() > 16 * KEPT_SEARCH_CACHE_BYTES, "la tabla: {} bytes", loose.memory_usage());
        drop(loose);

        let reference = regex::Regex::new(&groups(60)).unwrap();
        for _ in 0..2 {
            assert_eq!(big.captures(&text), reference_captures(&reference, &text));
            assert_eq!(big.kept_cache_bytes(), 0);
            assert_eq!(big.find_all(&text).len(), 40);
            assert_eq!(reference.find_iter(&text).count(), 40);
            assert_eq!(big.kept_cache_bytes(), 0);
            assert_eq!(big.replace_all(&text, "$1"), reference.replace_all(&text, "$1"));
            assert_eq!(big.kept_cache_bytes(), 0);
            assert!(big.is_match(&text));
            assert!(big.kept_cache_bytes() <= KEPT_SEARCH_CACHE_BYTES);
        }

        let small = LinearRegex::new(r"\w+").unwrap();
        assert_eq!(small.find_all(&text).len(), 40);
        let kept = small.kept_cache_bytes();
        assert!(kept > 0 && kept <= KEPT_SEARCH_CACHE_BYTES, "{}", kept);
        // La llamada siguiente usa esa caché: no vuelve a armar los estados que ya tenía.
        assert_eq!(small.find_all(&text).len(), 40);
        assert_eq!(small.kept_cache_bytes(), kept);
    }

    /// La caché sale del compilado mientras una búsqueda la usa: una búsqueda que empezara en el
    /// medio armaría la suya, y ninguna de las dos se pierde el resultado.
    #[test]
    fn a_search_inside_another_makes_its_own_cache() {
        let re = LinearRegex::new(r"\d+").unwrap();
        let mut inner = Vec::new();
        re.for_each_match("1 22 333", |start, end| {
            inner.push((start, end, re.find_all("4 55").len()));
        });
        assert_eq!(inner, vec![(0, 1, 2), (2, 4, 2), (5, 8, 2)]);
        assert!(re.kept_cache_bytes() > 0);
    }
}

//! `SynText` contra `String`: armar, clonar, agregar y soltar, compartido y único, en línea y en
//! el montón. Con Miri (`cargo +nightly miri test -p synsema-text`) estos mismos tests revisan el
//! `unsafe` (lecturas fuera de la asignación, usos después de soltar, fugas).

use synsema_text::{SynText, INLINE_MAX};

#[test]
fn inline_up_to_the_limit_and_heap_after() {
    let s: String = "abcdefghijklmnopqrstuvwxyz".repeat(2);
    for n in 0..s.len() {
        let t = SynText::from(&s[..n]);
        assert_eq!(t.as_str(), &s[..n]);
        assert_eq!(t.len(), n);
        // En línea no hay dueño único que mirar; en el montón, recién armado, es único.
        assert_eq!(t.is_unique(), n > INLINE_MAX, "n = {}", n);
    }
}

#[test]
fn utf8_at_every_boundary() {
    let s = "ñandú 🦀 añejo — 漢字 ok";
    let mut t = SynText::new();
    let mut want = String::new();
    for ch in s.chars() {
        t.push_str(ch.encode_utf8(&mut [0; 4]));
        want.push(ch);
        assert_eq!(t.as_str(), want);
    }
}

#[test]
fn a_clone_is_a_snapshot() {
    let mut a = SynText::from("hola");
    let b = a.clone();
    a.push_str(" mundo, esto ya no entra en línea");
    assert_eq!(b.as_str(), "hola");
    assert_eq!(a.as_str(), "hola mundo, esto ya no entra en línea");
    // Compartido en el montón: agregar copia y el otro dueño no ve nada.
    let c = a.clone();
    assert!(SynText::ptr_eq(&a, &c) && !a.is_unique());
    a.push_str("!");
    assert!(!SynText::ptr_eq(&a, &c));
    assert_eq!(c.as_str(), "hola mundo, esto ya no entra en línea");
    assert!(a.is_unique() && c.is_unique());
}

#[test]
fn unique_append_is_amortized() {
    let mut t = SynText::new();
    let mut want = String::new();
    for i in 0..20_000 {
        let piece = format!("{},", i);
        t.push_str(&piece);
        want.push_str(&piece);
    }
    assert_eq!(t.as_str(), want);
    assert!(t.is_unique());
}

#[test]
fn equality_hash_and_order_are_those_of_str() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let h = |x: &dyn Fn(&mut DefaultHasher)| {
        let mut s = DefaultHasher::new();
        x(&mut s);
        s.finish()
    };
    for s in ["", "a", "abcdefghijklmno", "abcdefghijklmnop", "una clave bastante más larga"] {
        let t = SynText::from(s);
        assert_eq!(h(&|x| t.hash(x)), h(&|x| s.hash(x)));
        assert_eq!(t, SynText::from(s.to_string()));
        let mut grown = SynText::from("");
        grown.push_str(s);
        assert_eq!(t, grown);
    }
    let mut v: Vec<SynText> = ["b", "a", "abcdefghijklmnopq", "ab"].iter().map(|s| SynText::from(*s)).collect();
    v.sort();
    let got: Vec<&str> = v.iter().map(|t| t.as_str()).collect();
    assert_eq!(got, ["a", "ab", "abcdefghijklmnopq", "b"]);
}

/// Operaciones al azar sobre un puñado de textos (algunos clones de otros) contra `String`.
#[test]
fn random_operations_match_string() {
    let mut seed: u64 = 0x5eed_7e47;
    let mut next = move |n: usize| {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        (seed.wrapping_mul(0x2545_F491_4F6C_DD1D) % n as u64) as usize
    };
    let pieces = ["", "a", "ñ", "🦀", "xyz", "0123456789", "una pieza más larga que quince bytes"];
    let rounds = if cfg!(miri) { 300 } else { 20_000 };
    let mut texts: Vec<SynText> = vec![SynText::new(); 6];
    let mut model: Vec<String> = vec![String::new(); 6];
    for _ in 0..rounds {
        let i = next(6);
        match next(5) {
            0 | 1 => {
                let p = pieces[next(pieces.len())];
                texts[i].push_str(p);
                model[i].push_str(p);
            }
            2 => {
                let j = next(6);
                texts[i] = texts[j].clone();
                model[i] = model[j].clone();
            }
            3 => {
                let p = pieces[next(pieces.len())];
                texts[i] = SynText::from(p);
                model[i] = p.to_string();
            }
            _ => {
                // Soltar y volver a vacío (a veces el último dueño).
                texts[i] = SynText::new();
                model[i].clear();
            }
        }
        for (t, m) in texts.iter().zip(&model) {
            assert_eq!(t.as_str(), m.as_str());
            assert_eq!(t.len(), m.len());
        }
    }
}

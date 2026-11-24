//! F4.8e: las listas de enteros y de floats sin caja (`SynList`) dan lo mismo que las de valores.
//! Cada caso arma la misma lista dos veces: con un literal (valores) y con `append` sobre una lista
//! vacía o con `range`/`apply` (sin caja), y compara lo que imprime todo lo que la toca.

use synsema_core::interpreter::run_source;

/// Un generador chico y determinista (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn int_lit(r: &mut Rng) -> String {
    match r.below(6) {
        0 => "0".into(),
        1 => format!("{}", r.below(5) as i64 - 2),
        2 => "9223372036854775807".into(),
        3 => "(0 - 9223372036854775807 - 1)".into(),
        _ => format!("{}", (r.next() % 2001) as i64 - 1000),
    }
}

fn float_lit(r: &mut Rng) -> String {
    match r.below(8) {
        0 => "0.0".into(),
        1 => "(0.0 - 0.0)".into(),
        2 => "(0.0 * -1.0)".into(),
        3 => "sqrt(0.0 - 1.0)".into(),
        4 => "1.5".into(),
        _ => format!("{}.25", (r.next() % 41) as i64 - 20),
    }
}

/// Lo que se le hace a cada lista (`xs`): todo lo que tiene que dar igual sin caja.
const OPS: &str = r#"print(xs)
print(sort(xs))
print(sort(xs, desc = true))
print(length(xs), xs == ys)
when length(xs) > 0
    print(xs[0], xs[-1], get(xs, 1, "no"))
print(apply(xs, (x) => x * 2))
print(where(xs, (x) => x > 0))
print(reduce(xs, (a, x) => a + x, 0))
print(count_where(xs, (x) => x == x))
let zs be xs
set zs to append(zs, 3)
print(xs, zs)
"#;

fn program(lits: &[String]) -> String {
    let lit = format!("[{}]", lits.join(", "));
    let mut s = format!("let ys be {}\nlet xs be []\n", lit);
    for l in lits {
        s += &format!("set xs to append(xs, {})\n", l);
    }
    s += OPS;
    // La misma lista como valores (el literal) con las mismas operaciones.
    s += &format!("let xs2 be {}\n", lit);
    s += &OPS.replace("xs", "xs2").replace("zs", "zs2");
    s
}

fn check(src: &str) {
    let r = run_source(src, "unboxed.syn");
    assert!(r.errors.is_empty() || !r.output.is_empty(), "{}\n{:?}", src, r.errors);
    // Las dos mitades imprimen lo mismo (la segunda con `xs2`, que en el texto no aparece).
    let n = r.output.len() / 2;
    assert_eq!(r.output.len() % 2, 0, "{}\n{:?}\n{:?}", src, r.output, r.errors);
    assert_eq!(r.output[..n], r.output[n..], "{}\n{:?}", src, r.errors);
}

#[test]
fn unboxed_lists_match_value_lists() {
    let mut r = Rng(0x5eed_f48e);
    for _ in 0..300 {
        let n = r.below(9) as usize;
        let floats = r.below(2) == 0;
        let lits: Vec<String> = (0..n).map(|_| if floats { float_lit(&mut r) } else { int_lit(&mut r) }).collect();
        check(&program(&lits));
    }
}

//! Fuzzing de `set` con camino (F4.6a de specs/compute-rendimiento.md) contra el tree-walker:
//! programas generados con una semilla fija sobre una estructura anidada de listas y mapas, con
//! alias tomados en distintos momentos (copy-on-write por nivel), la raíz en cada lugar donde la VM
//! la busca (global, variable de una vuelta, parámetro de una task compilada, global escrita desde
//! una task, frame que ve una closure) y a veces un camino que falla (fuera de rango, clave que no
//! está, índice que no es entero) o una clave nueva. Referencia y atajos tienen que dar la misma
//! salida, los mismos errores y los mismos `steps()`.
//!
//! `cargo test -p synsema-core --test set_path_fuzz` corre 200 programas; la corrida larga:
//! `cargo test -p synsema-core --test set_path_fuzz -- --ignored`.

use synsema_core::interpreter::{run_source, set_reference_mode};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, pct: usize) -> bool {
        self.below(100) < pct
    }
}

/// La estructura de partida. Cada lugar: su camino desde la raíz (en pasos) y si es un contenedor.
const START: &str = r#"{"a": [1, [2, 3], {"k": 4}], "b": {"x": [5, 6], "y": 7}, "c": 8}"#;

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Key(&'static str),
    Idx(i64),
}

/// Los contenedores (`true`) y las hojas (`false`) de `START`.
const PLACES: &[(&[Step], bool)] = &[
    (&[Step::Key("a")], true),
    (&[Step::Key("a"), Step::Idx(1)], true),
    (&[Step::Key("a"), Step::Idx(2)], true),
    (&[Step::Key("b")], true),
    (&[Step::Key("b"), Step::Key("x")], true),
    (&[Step::Key("a"), Step::Idx(0)], false),
    (&[Step::Key("a"), Step::Idx(1), Step::Idx(0)], false),
    (&[Step::Key("a"), Step::Idx(1), Step::Idx(1)], false),
    (&[Step::Key("a"), Step::Idx(2), Step::Key("k")], false),
    (&[Step::Key("b"), Step::Key("x"), Step::Idx(0)], false),
    (&[Step::Key("b"), Step::Key("x"), Step::Idx(1)], false),
    (&[Step::Key("b"), Step::Key("y")], false),
    (&[Step::Key("c")], false),
];

/// El largo de la lista que contiene un índice (para escribirlo negativo).
fn list_len(prefix: &[Step]) -> i64 {
    match prefix {
        [Step::Key("a")] => 3,
        [Step::Key("a"), Step::Idx(1)] | [Step::Key("b"), Step::Key("x")] => 2,
        _ => 1,
    }
}

struct Gen {
    rng: Rng,
}

impl Gen {
    /// Un camino escrito de varias formas: `.k`, `["k"]`, `[kv]`; índices literales, negativos o de
    /// una variable.
    fn path(&mut self, steps: &[Step], ivar: Option<&str>) -> String {
        let mut s = String::new();
        for (n, st) in steps.iter().enumerate() {
            match *st {
                Step::Key(k) => match self.rng.below(4) {
                    0 | 1 => s += &format!(".{}", k),
                    2 => s += &format!("[\"{}\"]", k),
                    _ => s += &format!("[key_{}]", k),
                },
                Step::Idx(i) => match self.rng.below(4) {
                    0 | 1 => s += &format!("[{}]", i),
                    2 => s += &format!("[{}]", i - list_len(&steps[..n])),
                    _ => match ivar {
                        // `(i - i + 1)`: el índice sale de una variable de la vuelta.
                        Some(v) => s += &format!("[{} - {} + {}]", v, v, i),
                        None => s += &format!("[{}]", i),
                    },
                },
            }
        }
        s
    }

    fn leaf(&mut self) -> &'static [Step] {
        loop {
            let (p, c) = PLACES[self.rng.below(PLACES.len())];
            if !c {
                return p;
            }
        }
    }

    /// Una sentencia sobre la raíz `r`. `aliases`: los alias de contenedores visibles (nombre y
    /// lugar); `ivar`: la variable de una vuelta, si hay.
    fn stmt(&mut self, r: &str, aliases: &[(String, usize)], ivar: Option<&str>, ind: &str) -> String {
        let roll = self.rng.below(200);
        if roll < 3 {
            // Un camino que falla.
            return match self.rng.below(4) {
                0 => format!("{}set {}.a[7] to 1\n", ind, r),
                1 => format!("{}set {}.nope.x to 1\n", ind, r),
                2 => format!("{}set {}.a[1][0.5] to 1\n", ind, r),
                _ => format!("{}set {}.c.x to 1\n", ind, r),
            };
        }
        if roll < 11 {
            // Una clave nueva en un mapa (no rompe ningún camino de `PLACES`).
            let v = ivar.unwrap_or("3");
            return format!("{}set {}{}.nuevo to {}\n", ind, r, self.path(&[Step::Key("b")], ivar), v);
        }
        if roll < 40 && !aliases.is_empty() {
            // Un contenedor pasa a ser un alias de la misma forma (comparten hasta que alguien
            // escriba).
            let (name, place) = &aliases[self.rng.below(aliases.len())];
            let p = self.path(PLACES[*place].0, ivar);
            return format!("{}set {}{} to {}\n", ind, r, p, name);
        }
        let dst = self.leaf();
        let p = self.path(dst, ivar);
        let val = match self.rng.below(3) {
            0 => format!("{}", self.rng.below(100)),
            1 => ivar.map(|v| format!("{} * 10", v)).unwrap_or_else(|| "11".to_string()),
            _ => {
                let src = self.leaf();
                format!("{}{} + 1", r, self.path(src, ivar))
            }
        };
        format!("{}set {}{} to {}\n", ind, r, p, val)
    }

    fn program(&mut self) -> String {
        let mut s = format!("let key_a be \"a\"\nlet key_b be \"b\"\nlet key_c be \"c\"\nlet key_k be \"k\"\nlet key_x be \"x\"\nlet key_y be \"y\"\nlet d be {}\n", START);
        let mut aliases: Vec<(String, usize)> = Vec::new();
        let mut shown = Vec::new();
        // Nivel superior: sentencias sueltas y alias.
        for _ in 0..3 {
            if self.rng.chance(50) {
                let (i, _) = PLACES.iter().enumerate().filter(|(_, (_, c))| *c).nth(self.rng.below(5)).unwrap();
                let name = format!("al{}", aliases.len());
                let p = self.path(PLACES[i].0, None);
                s += &format!("let {} be d{}\n", name, p);
                shown.push(name.clone());
                aliases.push((name, i));
            }
            s += &self.stmt("d", &aliases, None, "");
        }
        // Una vuelta de la VM (variable de la vuelta en la ventana, raíz global).
        s += "each i in range(0, 3)\n";
        for _ in 0..3 {
            s += &self.stmt("d", &aliases, Some("i"), "    ");
        }
        if self.rng.chance(40) {
            s += "    print(steps())\n";
        }
        // La raíz como variable de la vuelta (ventana).
        s += "each j in range(0, 2)\n    let w be d\n";
        for _ in 0..2 {
            s += &self.stmt("w", &aliases, Some("j"), "    ");
        }
        s += "    set d.c to w.c\n";
        // Un parámetro de una task que compila (se llama varias veces).
        s += "task t(p, n)\n";
        for _ in 0..3 {
            s += &self.stmt("p", &aliases, Some("n"), "    ");
        }
        s += "    give p\n";
        s += "let e1 be t(d, 0)\nlet e2 be t(e1, 1)\nlet e3 be t(d, 2)\nlet e4 be t(e3, 1)\n";
        // Una global escrita desde una task.
        s += "task g(n)\n";
        for _ in 0..2 {
            s += &self.stmt("d", &aliases, Some("n"), "    ");
        }
        s += "    give n\n";
        s += "each q in range(0, 3)\n    g(q)\n";
        // Un frame que ve una closure.
        s += "task h(n)\n    let loc be d\n    let peek be () => loc.a\n";
        for _ in 0..2 {
            s += &self.stmt("loc", &aliases, Some("n"), "    ");
        }
        s += "    give [loc, peek()]\n";
        s += "let h1 be h(0)\nlet h2 be h(1)\nlet h3 be h(2)\n";
        s += &format!("print(d, e1, e2, e3, e4, h1, h2, h3{}{})\n", if shown.is_empty() { "" } else { ", " }, shown.join(", "));
        s += "print(steps())\n";
        s
    }
}

/// El modo referencia es global al proceso: un solo `check` a la vez.
static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn check(seed: u64, count: usize) {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = Gen { rng: Rng(seed) };
    let mut failures = Vec::new();
    let mut errors = 0;
    for i in 0..count {
        let src = g.program();
        set_reference_mode(true);
        let reference = run_source(&src, "fuzz.syn");
        set_reference_mode(false);
        let fast = run_source(&src, "fuzz.syn");
        if !reference.success {
            errors += 1;
        }
        if (reference.success, &reference.output, &reference.errors) != (fast.success, &fast.output, &fast.errors) {
            failures.push(format!(
                "programa {} (semilla {:#x}):\n{}\nreferencia: {:?} {:?}\natajos:     {:?} {:?}",
                i, seed, src, reference.output, reference.errors, fast.output, fast.errors
            ));
        }
    }
    eprintln!("set_path_fuzz: {} programas ({} terminan en error)", count, errors);
    assert!(failures.is_empty(), "{} programa(s) dan distinto:\n\n{}", failures.len(), failures.join("\n\n"));
    // Que el generador no sea todo errores (cada error corta el programa ahí).
    assert!(errors < count / 2, "demasiados programas terminan en error: {}", errors);
}

#[test]
fn set_paths_match_the_reference_on_generated_programs() {
    check(0x5e7_f46a_01, 200);
}

#[test]
#[ignore]
fn set_paths_match_the_reference_on_many_generated_programs() {
    check(0x5e7_f46a_0000_0002, 3000);
}

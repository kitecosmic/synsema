//! Fuzzing del nivel nativo contra el tree-walker (spec §F4.6): programas numéricos generados con
//! una semilla fija (tasks con locales, `while` acotados, recursión, llamadas entre tasks, `when`,
//! constantes en los bordes de i64 y `%` que a veces divide por cero), cada uno corrido con la
//! referencia y con el nivel nativo ansioso. Tienen que dar la misma salida, los mismos errores y
//! los mismos `steps()` (el programa los imprime al final).
//!
//! `cargo test -p synsema-jit --test fuzz` corre 150 programas; la corrida larga:
//! `cargo test -p synsema-jit --test fuzz -- --ignored`.

use synsema_core::interpreter::{run_source, set_reference_mode};
use synsema_core::native_tier;

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

/// Constantes: chicas, y en los bordes de i64 (sin literales negativos: `-x` es un operador que el
/// nivel nativo no compila en F4.1).
const CONSTS: &[&str] = &[
    "0", "1", "2", "3", "7", "10", "100", "(0 - 1)", "(0 - 7)", "2147483647", "4611686018427387904",
    "9223372036854775807", "(0 - 9223372036854775807)", "3037000499", "3037000500",
];

struct Gen {
    rng: Rng,
}

impl Gen {
    fn atom(&mut self, vars: &[String]) -> String {
        if !vars.is_empty() && self.rng.chance(65) {
            vars[self.rng.below(vars.len())].clone()
        } else {
            CONSTS[self.rng.below(CONSTS.len())].to_string()
        }
    }

    fn expr(&mut self, vars: &[String], depth: usize) -> String {
        if depth == 0 || self.rng.chance(30) {
            return self.atom(vars);
        }
        let a = self.expr(vars, depth - 1);
        let b = self.expr(vars, depth - 1);
        match self.rng.below(5) {
            0 => format!("({} + {})", a, b),
            1 => format!("({} - {})", a, b),
            2 => format!("({} * {})", a, b),
            // Casi siempre un divisor que no es cero (`x % 5 + 6` está entre 6 y 10); a veces, uno
            // cualquiera (el error de la VM, con su ubicación).
            3 if self.rng.chance(90) => format!("({} % ({} % 5 + 6))", a, b),
            3 => format!("({} % {})", a, b),
            _ => format!("({} % 1000)", a),
        }
    }

    fn cond(&mut self, vars: &[String]) -> String {
        let ops = ["<", "<=", ">", ">=", "==", "!="];
        let a = self.expr(vars, 1);
        let b = self.expr(vars, 1);
        format!("{} {} {}", a, ops[self.rng.below(ops.len())], b)
    }

    /// Una task de cómputo: locales, un `when` que puede salir antes, un `while` acotado.
    fn plain_task(&mut self, name: &str, nparams: usize, callee: Option<(&str, usize)>) -> String {
        let params: Vec<String> = (0..nparams).map(|i| format!("p{}", i)).collect();
        let mut vars = params.clone();
        let mut s = format!("task {}({})\n", name, params.join(", "));
        for l in ["x", "y"] {
            let e = self.expr(&vars, 2);
            s += &format!("    let {} be {}\n", l, e);
            vars.push(l.to_string());
        }
        if self.rng.chance(50) {
            let c = self.cond(&vars);
            let e = self.expr(&vars, 2);
            s += &format!("    when {}\n        give {}\n", c, e);
        }
        if self.rng.chance(70) {
            let bound = self.rng.below(7);
            s += &format!("    let k be 0\n    while k < {}\n", bound);
            let e = self.expr(&vars, 2);
            s += &format!("        set x to {}\n", e);
            if self.rng.chance(50) {
                let c = self.cond(&vars);
                let e = self.expr(&vars, 2);
                s += &format!("        when {}\n            set y to {}\n", c, e);
            }
            s += "        set k to k + 1\n";
        }
        if let Some((f, n)) = callee {
            let args: Vec<String> = (0..n).map(|_| self.expr(&vars, 1)).collect();
            s += &format!("    let z be {}({})\n", f, args.join(", "));
            vars.push("z".to_string());
        }
        if self.rng.chance(15) {
            let c = self.cond(&vars);
            s += &format!("    give {}\n", c);
        } else {
            let e = self.expr(&vars, 2);
            s += &format!("    give {}\n", e);
        }
        s
    }

    /// Una task recursiva: `n` baja de a uno hasta 0. El argumento que pasa va acotado (`% 1000003`):
    /// si no, `a * a` en cada nivel da un número de 2^(2^25) bits (en la referencia igual).
    fn rec_task(&mut self, name: &str) -> String {
        let vars = vec!["n".to_string(), "a".to_string()];
        let base = self.expr(&vars[1..], 1);
        let step = self.expr(&vars, 1);
        let arg = self.expr(&vars, 1);
        format!(
            "task {name}(n, a)\n    when n <= 0\n        give {base}\n    give {step} + {name}(n - 1, {arg} % 1000003)\n"
        )
    }

    fn program(&mut self) -> String {
        let mut s = String::new();
        let n0 = 1 + self.rng.below(3);
        s += &self.plain_task("f0", n0, None);
        let n1 = 1 + self.rng.below(3);
        s += &self.plain_task("f1", n1, Some(("f0", n0)));
        s += &self.rec_task("r0");
        // Las llamadas desde un solo sitio, en un bucle (así ese sitio entra al código nativo).
        let rows: Vec<String> = (0..8)
            .map(|_| {
                let vals: Vec<String> = (0..3).map(|_| CONSTS[self.rng.below(CONSTS.len())].to_string()).collect();
                let depth = self.rng.below(25);
                format!("[{}, {}]", vals.join(", "), depth)
            })
            .collect();
        s += &format!("let out be []\neach p in [{}]\n", rows.join(", "));
        let a0: Vec<String> = (0..n0).map(|i| format!("p[{}]", i % 3)).collect();
        let a1: Vec<String> = (0..n1).map(|i| format!("p[{}]", (i + 1) % 3)).collect();
        s += &format!("    let u be f0({})\n", a0.join(", "));
        s += &format!("    let v be f1({})\n", a1.join(", "));
        s += "    let w be r0(p[3], p[0])\n";
        s += "    set out to append(out, [u, v, w])\n";
        s += "print(out)\nprint(steps())\n";
        s
    }
}

/// El modo referencia es global al proceso: un solo `check` a la vez.
static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn check(seed: u64, count: usize) {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    synsema_jit::install();
    native_tier::set_eager(true);
    let before = native_tier::stats();
    let mut g = Gen { rng: Rng(seed) };
    let mut failures = Vec::new();
    let mut errors = 0;
    for i in 0..count {
        let src = g.program();
        set_reference_mode(true);
        let reference = run_source(&src, "fuzz.syn");
        set_reference_mode(false);
        let native = run_source(&src, "fuzz.syn");
        if !reference.success {
            errors += 1;
        }
        if (reference.success, &reference.output, &reference.errors) != (native.success, &native.output, &native.errors) {
            failures.push(format!(
                "programa {} (semilla {}):\n{}\nreferencia: {:?} {:?}\nnativo:     {:?} {:?}",
                i, seed, src, reference.output, reference.errors, native.output, native.errors
            ));
        }
    }
    let after = native_tier::stats();
    eprintln!(
        "fuzz: {} programas ({} terminan en error), {} unidades, {} entradas, {} salidas a la VM",
        count,
        errors,
        after.units - before.units,
        after.entries - before.entries,
        after.deopts - before.deopts
    );
    assert!(failures.is_empty(), "{} programa(s) dan distinto en nativo:\n\n{}", failures.len(), failures.join("\n\n"));
    assert!(after.entries - before.entries > count as u64, "el nivel nativo casi no corrió: {:?} → {:?}", before, after);
    assert!(after.deopts > before.deopts, "ningún programa salió a la VM a mitad de camino");
}

#[test]
fn native_matches_the_reference_on_generated_programs() {
    check(0x5eed_f4_01, 150);
}

#[test]
#[ignore]
fn native_matches_the_reference_on_many_generated_programs() {
    check(0xf4_1_0000_0001, 3000);
}

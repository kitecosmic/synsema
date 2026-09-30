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
            // F4.2b: a veces un `each` sobre `range` (con paso negativo o desde un parámetro).
            let each = self.rng.chance(50);
            if each {
                let r = match self.rng.below(3) {
                    0 => format!("range({})", bound),
                    1 => format!("range({}, 0, 0 - {})", bound, 1 + self.rng.below(3)),
                    _ => format!("range(0, {} % 7, 2)", vars[0]),
                };
                s += &format!("    each k in {}\n", r);
            } else {
                s += &format!("    let k be 0\n    while k < {}\n", bound);
            }
            let e = self.expr(&vars, 2);
            s += &format!("        set x to {}\n", e);
            if self.rng.chance(50) {
                let c = self.cond(&vars);
                let e = self.expr(&vars, 2);
                s += &format!("        when {}\n            set y to {}\n", c, e);
            }
            if !each {
                s += "        set k to k + 1\n";
            }
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

    /// F4.2: un bucle del nivel superior sobre globales (pasa a nativo a mitad de camino). Lo que
    /// asigna va acotado (`% 1000003`) para que no crezca sin fin; a veces llama a una task, a
    /// veces corta con `stop` y a veces declara con `let` en el nivel del bucle.
    fn top_loop(&mut self, call: (&str, usize)) -> String {
        let vars: Vec<String> = ["g0", "g1", "lc"].iter().map(|v| v.to_string()).collect();
        let bound = 2 + self.rng.below(40);
        let mut s = format!("let g0 be {}\nlet g1 be {}\nlet lc be 0\nlet gl be 0\n", self.atom(&[]), self.atom(&[]));
        // F4.2b: la mitad de las veces un `each` sobre `range` (la variable de la vuelta, `ev`).
        let each = self.rng.chance(50);
        if each {
            s += &format!("each ev in range(0, {}, {})\n    set lc to lc + ev % 2\n", 3 * bound, 1 + self.rng.below(3));
        } else {
            s += &format!("while lc < {}\n", bound);
        }
        let e = self.expr(&vars, 2);
        s += &format!("    set g0 to ({}) % 1000003\n", e);
        if self.rng.chance(50) {
            let c = self.cond(&vars);
            let e = self.expr(&vars, 2);
            s += &format!("    when {}\n        set g1 to ({}) % 1000003\n", c, e);
        }
        if self.rng.chance(40) {
            let args: Vec<String> = (0..call.1).map(|_| self.expr(&vars, 1)).collect();
            s += &format!("    set g1 to (g1 + {}({})) % 1000003\n", call.0, args.join(", "));
        }
        if self.rng.chance(30) {
            let e = self.expr(&vars, 1);
            s += &format!("    let gl be {}\n", e);
        }
        if self.rng.chance(25) {
            let c = self.cond(&vars);
            s += &format!("    when {}\n        stop\n", c);
        }
        if !each {
            s += "    set lc to lc + 1\n";
        }
        s += "print([g0, g1, lc, gl])\n";
        s
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
        s += "print(out)\n";
        s += &self.top_loop(("f0", n0));
        s += "print(steps())\n";
        s
    }
}

/// F4.7: constantes con floats: bordes de la comparación exacta (2^53 ± 1, 2^63, fracciones
/// negativas), `-0.0`, infinitos y NaN, y enteros que se mezclan con ellos.
const FCONSTS: &[&str] = &[
    "0.0", "-0.0", "0.5", "1.5", "-2.5", "3.0", "0.1", "1.0e308", "(1.0e308 * 10.0)", "(-(1.0e308 * 10.0))",
    "(1.0e308 * 10.0 - 1.0e308 * 10.0)", "9007199254740992.0", "9007199254740993", "9007199254740992",
    "9223372036854775807.0", "(-9223372036854775807.0)", "9223372036854775807", "4611686018427387904.0", "2", "7", "0",
    "(0 - 3)", "(0 - 9223372036854775807 - 1)",
];

struct FGen {
    rng: Rng,
}

impl FGen {
    fn atom(&mut self, vars: &[String]) -> String {
        if !vars.is_empty() && self.rng.chance(60) {
            vars[self.rng.below(vars.len())].clone()
        } else {
            FCONSTS[self.rng.below(FCONSTS.len())].to_string()
        }
    }

    fn expr(&mut self, vars: &[String], depth: usize) -> String {
        if depth == 0 || self.rng.chance(30) {
            return self.atom(vars);
        }
        let a = self.expr(vars, depth - 1);
        let b = self.expr(vars, depth - 1);
        match self.rng.below(10) {
            0 => format!("({} + {})", a, b),
            1 => format!("({} - {})", a, b),
            2 => format!("({} * {})", a, b),
            // A veces un divisor cero (también `-0.0`): el error de la VM, con su ubicación.
            3 if self.rng.chance(15) => format!("({} / {})", a, b),
            3 | 4 => format!("({} / ({} * {} + 0.5))", a, b, b),
            // `-(…)`: `--` es un comentario.
            5 => format!("(-({}))", a),
            // F4.7c: los intrínsecos (un negativo a `sqrt` da NaN; `abs` de `i64::MIN` es un `Big`).
            6 => format!("sqrt({})", a),
            7 => format!("abs({})", a),
            8 => format!("float({})", a),
            _ => format!("({} * 0.5)", a),
        }
    }

    fn cond(&mut self, vars: &[String]) -> String {
        let ops = ["<", "<=", ">", ">=", "==", "!="];
        let a = self.expr(vars, 1);
        let b = self.expr(vars, 1);
        let c = format!("{} {} {}", a, ops[self.rng.below(ops.len())], b);
        match self.rng.below(10) {
            0 => format!("not ({})", c),
            // Un entero y un float en el borde de la comparación exacta (uno de los dos, a veces,
            // una variable que puede tenerlo).
            8 | 9 => {
                let ib = ["9007199254740993", "9007199254740992", "9223372036854775807", "(0 - 9223372036854775807 - 1)", "(0 - 3)", "2"];
                let fb = ["9007199254740992.0", "9223372036854775807.0", "(-9223372036854775807.0)", "-2.5", "2.0", "(1.0e308 * 10.0)", "(1.0e308 * 10.0 - 1.0e308 * 10.0)"];
                let i = if !vars.is_empty() && self.rng.chance(30) { vars[self.rng.below(vars.len())].clone() } else { ib[self.rng.below(ib.len())].to_string() };
                let f = fb[self.rng.below(fb.len())];
                let op = ops[self.rng.below(ops.len())];
                if self.rng.chance(50) { format!("{} {} {}", i, op, f) } else { format!("{} {} {}", f, op, i) }
            }
            // La veracidad de un número (`-0.0` y `0.0` son falsos, NaN verdadero).
            6 => self.expr(vars, 1),
            7 => format!("not ({})", self.expr(vars, 1)),
            1 => {
                let d = self.expr(vars, 0);
                format!("({}) and {} != 0", c, d)
            }
            _ => c,
        }
    }

    /// Lo que se asigna en un bucle: acotado para que los enteros no crezcan sin fin (un `Big` de
    /// millones de dígitos); a veces un entero, un decimal o `nothing` (el tipo cambia a mitad).
    fn value(&mut self, vars: &[String]) -> String {
        match self.rng.below(100) {
            0..=9 => "7".to_string(),
            10..=14 => "(0 - 3)".to_string(),
            5 => "1.5d".to_string(),
            _ => {
                let e = self.expr(vars, 2);
                format!("({}) * 0.5 + {}", e, FCONSTS[self.rng.below(7)])
            }
        }
    }

    fn task(&mut self, name: &str, nparams: usize, callee: Option<(&str, usize)>) -> String {
        let params: Vec<String> = (0..nparams).map(|i| format!("p{}", i)).collect();
        let mut vars = params.clone();
        let mut s = format!("task {}({})\n", name, params.join(", "));
        for l in ["x", "y"] {
            let e = self.value(&vars);
            s += &format!("    let {} be {}\n", l, e);
            vars.push(l.to_string());
        }
        if self.rng.chance(40) {
            let c = self.cond(&vars);
            let e = self.expr(&vars, 2);
            s += &format!("    when {}\n        give {}\n", c, e);
        }
        if self.rng.chance(70) {
            let bound = self.rng.below(7);
            let each = self.rng.chance(50);
            if each {
                s += &format!("    each k in range({})\n", bound);
            } else {
                s += &format!("    let k be 0\n    while k < {}\n", bound);
            }
            let e = self.value(&vars);
            s += &format!("        set x to {}\n", e);
            if self.rng.chance(50) {
                let c = self.cond(&vars);
                let e = self.value(&vars);
                s += &format!("        when {}\n            set y to {}\n", c, e);
            }
            if !each {
                s += "        set k to k + 1\n";
            }
        }
        if let Some((f, n)) = callee {
            let args: Vec<String> = (0..n).map(|_| self.expr(&vars, 1)).collect();
            s += &format!("    let z be {}({})\n", f, args.join(", "));
            vars.push("z".to_string());
        }
        if self.rng.chance(8) {
            let c = self.cond(&vars);
            s += &format!("    give {}\n", c);
        } else {
            let e = self.expr(&vars, 2);
            s += &format!("    give {}\n", e);
        }
        s
    }

    /// Un bucle del nivel superior sobre globales con floats: tipos que cambian (un entero, un
    /// decimal, `nothing`), `stop`, llamadas a una task.
    fn top_loop(&mut self, call: (&str, usize)) -> String {
        let vars: Vec<String> = ["g0", "g1", "lc"].iter().map(|v| v.to_string()).collect();
        let bound = 2 + self.rng.below(40);
        let a0 = self.atom(&[]);
        let a1 = self.atom(&[]);
        let mut s = format!("let g0 be {}\nlet g1 be {}\nlet lc be 0\nlet g2 be 0.5\nlet cnt be 0\n", a0, a1);
        if self.rng.chance(50) {
            s += &format!("each ev in range(0, {})\n    set lc to lc + 1\n", bound);
        } else {
            s += &format!("while lc < {}\n    set lc to lc + 1\n", bound);
        }
        // Un `+` que la VM especializó con un `Float` y después recibe dos enteros: la guarda de
        // `FloatArith` tiene que salir (con enteros, `2**53 + 1 + 2` es exacto; en f64, no).
        if self.rng.chance(50) {
            s += "    when g2 + 9007199254740993 == 9007199254740995\n        set cnt to cnt + 1\n";
            s += "    when lc % 2 == 0 and lc > 4\n        set g2 to 2\n    when lc % 2 == 1\n        set g2 to 0.5\n";
        }
        let e = self.value(&vars);
        s += &format!("    set g0 to {}\n", e);
        if self.rng.chance(50) {
            let c = self.cond(&vars);
            let e = self.value(&vars);
            s += &format!("    when {}\n        set g1 to {}\n", c, e);
        }
        if self.rng.chance(40) {
            let args: Vec<String> = (0..call.1).map(|_| self.expr(&vars, 1)).collect();
            s += &format!("    set g1 to g1 + {}({})\n", call.0, args.join(", "));
        }
        if self.rng.chance(25) {
            let c = self.cond(&vars);
            s += &format!("    when {}\n        stop\n", c);
        }
        s += "print([g0, g1, lc, g2, cnt])\n";
        s
    }

    fn program(&mut self) -> String {
        let mut s = String::new();
        let n0 = 1 + self.rng.below(3);
        s += &self.task("f0", n0, None);
        let n1 = 1 + self.rng.below(3);
        s += &self.task("f1", n1, Some(("f0", n0)));
        // Un `let` en un `when` que se lee después: un lugar de la ventana que según el camino
        // está vacío (vacío, la VM lo busca por nombre y da su error).
        let q = ["q".to_string()];
        let c = if self.rng.chance(20) { self.cond(&q) } else { "i != 5".to_string() };
        let e = self.expr(&q, 1);
        s += &format!(
            "task h(q)\n    let acc be 0.0\n    each i in range(3)\n        when {}\n            let t be {}\n        when i == 1\n            set acc to acc + t\n    give acc\n",
            c, e
        );
        // Cada columna casi siempre del mismo tipo (así la task entra por `CallNative` con
        // parámetros `Float`); a veces una fila distinta (la guarda de la entrada).
        let floats = ["0.5", "1.5", "-2.5", "3.0", "0.1", "-0.0", "9007199254740992.0", "(1.0e308 * 10.0)"];
        let ints = ["2", "7", "0", "(0 - 3)", "9007199254740993"];
        let kinds: Vec<bool> = (0..3).map(|_| self.rng.chance(75)).collect();
        let rows: Vec<String> = (0..8)
            .map(|_| {
                let vals: Vec<String> = (0..3)
                    .map(|c| {
                        let fl = if self.rng.chance(10) { !kinds[c] } else { kinds[c] };
                        if fl { floats[self.rng.below(floats.len())] } else { ints[self.rng.below(ints.len())] }.to_string()
                    })
                    .collect();
                format!("[{}]", vals.join(", "))
            })
            .collect();
        s += &format!("let out be []\neach p in [{}]\n", rows.join(", "));
        let a0: Vec<String> = (0..n0).map(|i| format!("p[{}]", i % 3)).collect();
        let a1: Vec<String> = (0..n1).map(|i| format!("p[{}]", (i + 1) % 3)).collect();
        s += &format!("    let u be f0({})\n", a0.join(", "));
        s += &format!("    let v be f1({})\n", a1.join(", "));
        s += "    let w be h(p[2])\n";
        s += "    set out to append(out, [u, v, w])\n";
        s += "print(out)\n";
        s += &self.top_loop(("f0", n0));
        s += "print(steps())\n";
        s
    }
}

/// F4.7b: generador de programas que LEEN datos en bucles nativos: listas (de enteros, floats,
/// mezcladas, anidadas), mapas con forma y en modo diccionario, registros con la misma forma o con
/// formas distintas, alias, escrituras a mitad del bucle (salen a la VM: el copy-on-write lo ve),
/// `each` sobre una lista que el cuerpo modifica (la referencia recorre una foto), índices fuera de
/// rango, negativos o que no son enteros, claves que faltan, `stop`.
struct DGen {
    rng: Rng,
}

impl DGen {
    fn elem(&mut self) -> String {
        let pool = ["0", "1", "2", "-3", "7", "2.5", "-0.5", "0.0", "9007199254740993", "\"t\"", "\"\"", "nothing", "true", "[1, 2]", "[]", "{\"a\": 1}"];
        // Casi siempre números (lo que el bucle suma); a veces otra cosa (el error de la VM).
        if self.rng.chance(85) {
            pool[self.rng.below(9)].to_string()
        } else {
            pool[self.rng.below(pool.len())].to_string()
        }
    }

    fn list(&mut self, n: usize) -> String {
        let v: Vec<String> = (0..n).map(|_| self.elem()).collect();
        format!("[{}]", v.join(", "))
    }

    fn record(&mut self, shape: usize) -> String {
        let keys: &[&str] = match shape {
            0 => &["x", "y", "m"],
            1 => &["y", "x", "m"],
            2 => &["x", "m"],
            _ => &["x", "y", "m", "z"],
        };
        let v: Vec<String> = keys.iter().map(|k| format!("\"{}\": {}", k, self.elem())).collect();
        format!("{{{}}}", v.join(", "))
    }

    /// Una lectura (lo que el bucle suma o compara).
    fn read(&mut self) -> String {
        match self.rng.below(12) {
            0 | 1 => "xs[i % n]".to_string(),
            2 => format!("xs[i % n - {}]", self.rng.below(4)),
            // Fuera de rango, a veces.
            3 if self.rng.chance(20) => "xs[i + 2]".to_string(),
            3 => "xs[(i * 7) % n]".to_string(),
            4 => "grid[i % 3][(i + 1) % 4]".to_string(),
            5 => "recs[i % 4].x".to_string(),
            6 => "recs[i % 4].m".to_string(),
            7 => "m[\"a\"]".to_string(),
            8 => "m[keys[i % 4]]".to_string(),
            9 => "big[bigkeys[i % 40]]".to_string(),
            10 => "alias[i % n]".to_string(),
            // Una clave que no es texto en un mapa (lo resuelve la VM).
            11 if self.rng.chance(15) => "m[i % 2]".to_string(),
            // F4.7c: `length` de una lista, de un mapa, de un registro, de un elemento (a veces no
            // tiene largo: el error de la VM).
            11 if self.rng.chance(40) => ["length(xs)", "length(m)", "length(recs[i % 4])", "length(grid[i % 3])", "length(xs[i % n])"][self.rng.below(5)].to_string(),
            _ => "m.b".to_string(),
        }
    }

    fn program(&mut self) -> String {
        let n = 3 + self.rng.below(5);
        let mut s = String::new();
        s += &format!("let xs be {}\nlet n be length(xs)\n", self.list(n));
        let rows: Vec<String> = (0..3).map(|_| self.list(4)).collect();
        s += &format!("let grid be [{}]\n", rows.join(", "));
        // Registros: la misma forma, o formas distintas (la caché por forma ve varias).
        let poly = self.rng.chance(40);
        let recs: Vec<String> = (0..4).map(|k| { let sh = if poly { k % 4 } else { 0 }; self.record(sh) }).collect();
        s += &format!("let recs be [{}]\n", recs.join(", "));
        s += &format!("let m be {{\"a\": {}, \"b\": {}, \"c\": 3}}\n", self.elem(), self.elem());
        // A veces falta una clave (el error de la VM).
        // A veces falta una clave, o una no es texto (el error de la VM; en la cuarta posición: el
        // bucle ya está en nativo cuando llega).
        let keys = match self.rng.below(10) {
            0 | 1 => "[\"a\", \"b\", \"c\", \"zz\"]",
            2 => "[\"a\", \"b\", \"c\", 1]",
            _ => "[\"a\", \"b\", \"c\", \"a\"]",
        };
        s += &format!("let keys be {}\n", keys);
        // Un mapa de 40 claves: modo diccionario.
        s += "let big be {}\nlet bigkeys be []\neach k in range(0, 40)\n    set big[\"k\" + text(k)] to k * 2\n    set bigkeys to append(bigkeys, \"k\" + text(k))\n";
        s += "let alias be xs\n";
        s += "let acc be 0\nlet facc be 0.0\nlet cnt be 0\n";
        let bound = 3 + self.rng.below(30);
        let over_list = self.rng.chance(35);
        // El bucle (sus líneas, sin la sangría de un bucle de afuera).
        let mut lp = String::new();
        if over_list {
            // Casi siempre una lista; a veces un mapa o un texto (sus claves, sus caracteres: el
            // `each` sobre ellos lo hace la VM), o algo que no se recorre (su error).
            let coll = match self.rng.below(10) {
                0 => "m",
                1 => "\"abc\"",
                2 if self.rng.chance(30) => "n",
                _ => "xs",
            };
            lp += &format!("let i be 0\neach v in {}\n    set i to i + 1\n", coll);
            lp += "    when v\n        set cnt to cnt + 1\n";
            if self.rng.chance(60) {
                lp += "    set facc to facc + v * 1.0\n";
            }
            if self.rng.chance(30) {
                // El cuerpo cambia la lista que recorre: la referencia sigue con la foto.
                lp += "    when i == 2\n        set xs to append(xs, 5)\n";
            }
        } else {
            lp += &format!("each i in range(0, {})\n", bound);
        }
        for _ in 0..1 + self.rng.below(3) {
            let r = self.read();
            match self.rng.below(4) {
                0 => lp += &format!("    set facc to facc + {} * 0.5\n", r),
                1 => lp += &format!("    when {} > 1\n        set cnt to cnt + 1\n", r),
                2 => lp += &format!("    let t be {}\n    when t\n        set cnt to cnt + 1\n", r),
                _ => lp += &format!("    set acc to acc + {}\n", r),
            }
        }
        // Escrituras a mitad del bucle (salen a la VM): el alias no cambia (copy-on-write).
        if self.rng.chance(35) {
            lp += "    when i % 5 == 1\n        set xs[0] to xs[0] + 1\n";
        }
        if self.rng.chance(25) {
            lp += "    when i % 7 == 3\n        set recs[1].x to i\n";
        }
        if self.rng.chance(20) {
            lp += "    when i == 4\n        set m.a to 2.5\n";
        }
        if self.rng.chance(15) {
            lp += "    when acc > 20\n        stop\n";
        }
        // A veces dentro de otro bucle: así el comienzo del `each` (sobre una lista o sobre otra
        // cosa) también corre en nativo.
        if self.rng.chance(40) {
            s += "each rep in range(0, 3)\n";
            for l in lp.lines() {
                s += &format!("    {}\n", l);
            }
        } else {
            s += &lp;
        }
        s += "print([acc, facc, cnt, xs, alias, recs[1], m])\n";
        s += "print(steps())\n";
        s
    }
}

/// El modo referencia es global al proceso: un solo `check` a la vez.
static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn check(seed: u64, count: usize) {
    let mut g = Gen { rng: Rng(seed) };
    check_with(seed, count, true, move || g.program());
}

/// `tasks`: los programas llaman tasks desde un sitio caliente (se exige que entren al código nativo).
fn check_with(seed: u64, count: usize, tasks: bool, mut program: impl FnMut() -> String) {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    synsema_jit::install();
    native_tier::set_eager(true);
    let before = native_tier::stats();
    let mut failures = Vec::new();
    let mut errors = 0;
    for i in 0..count {
        let src = program();
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
        "fuzz: {} programas ({} terminan en error), {} unidades, {} entradas, {} salidas a la VM, {} entradas a bucles",
        count,
        errors,
        after.units - before.units,
        after.entries - before.entries,
        after.deopts - before.deopts,
        after.osr - before.osr
    );
    assert!(failures.is_empty(), "{} programa(s) dan distinto en nativo:\n\n{}", failures.len(), failures.join("\n\n"));
    // Un generador que arma programas que fallan todos no prueba nada (pasó: un builtin que no está
    // en core).
    assert!(errors * 4 < count * 3, "{} de {} programas terminan en error: el generador está roto", errors, count);
    assert!(!tasks || after.entries - before.entries > count as u64, "el nivel nativo casi no corrió: {:?} → {:?}", before, after);
    assert!(after.deopts > before.deopts, "ningún programa salió a la VM a mitad de camino");
    assert!(after.osr - before.osr > count as u64 / 2, "los bucles del nivel superior casi no entraron al código nativo: {:?} → {:?}", before, after);
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

/// F4.7: programas con floats (`FloatArith`, `NumCmp` exacto, `-0.0`, NaN, infinitos, `/` por
/// cero, decimal⊕float a mitad de un bucle, tipos que cambian, lugares que según el camino están
/// vacíos, tasks con parámetros `Float`).
#[test]
fn native_matches_the_reference_on_float_programs() {
    let mut g = FGen { rng: Rng(0x5eed_f4_07) };
    check_with(0x5eed_f4_07, 150, true, move || g.program());
}

#[test]
#[ignore]
fn native_matches_the_reference_on_many_float_programs() {
    let mut g = FGen { rng: Rng(0xf4_7_0000_0001) };
    check_with(0xf4_7_0000_0001, 3000, true, move || g.program());
}

/// F4.7b: programas que leen datos en bucles nativos (listas, anidadas, mapas con forma y en modo
/// diccionario, registros de varias formas, alias, escrituras que salen a la VM, `each` sobre una
/// lista que el cuerpo cambia, índices y claves que fallan).
#[test]
fn native_matches_the_reference_on_data_programs() {
    let mut g = DGen { rng: Rng(0x5eed_f4_7b) };
    check_with(0x5eed_f4_7b, 200, false, move || g.program());
}

#[test]
#[ignore]
fn native_matches_the_reference_on_many_data_programs() {
    let mut g = DGen { rng: Rng(0xf4_7b_0000_0001) };
    check_with(0xf4_7b_0000_0001, 3000, false, move || g.program());
}

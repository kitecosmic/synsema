//! Fuzzing de las cadenas `set P to P + e1 + … + ek` (F4.6c de specs/compute-rendimiento.md) contra
//! el tree-walker: programas generados con una semilla fija que repiten cada cadena en una vuelta
//! (la primera corre genérica y las siguientes en modo texto), con P en cada lugar donde la VM la
//! escribe (global, variable de una vuelta, parámetro de una task compilada, local de un frame que
//! ve una closure, global escrita desde una task), piezas de todos los tipos (textos en línea y en
//! el montón, UTF-8, números, bools, la propia P, `length(P)`, una task que religa P o le agrega),
//! alias tomados en el camino y a veces una pieza que no se suma a un texto en una vuelta ya
//! especializada. Referencia y atajos tienen que dar la misma salida, los mismos errores y los
//! mismos `steps()`.
//!
//! `cargo test -p synsema-core --test text_chain_fuzz` corre 200 programas; la corrida larga:
//! `cargo test -p synsema-core --test text_chain_fuzz -- --ignored`.

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

struct Gen {
    rng: Rng,
}

impl Gen {
    /// Una pieza para una cadena sobre `p` (`i`: la variable de la vuelta; `global`: si `p` es la
    /// global `s`, que las tasks `rebind`/`grow` escriben).
    fn piece(&mut self, p: &str, i: &str, global: bool) -> String {
        match self.rng.below(if global { 16 } else { 14 }) {
            0 => "\"a\"".to_string(),
            1 => "\"una pieza que no entra en línea\"".to_string(),
            2 => "\"ñ\"".to_string(),
            3 => "\"🦀\"".to_string(),
            4 => format!("text({})", i),
            5 => i.to_string(),
            6 => format!("({} / 2)", i),
            7 => format!("({} > 1)", i),
            // La global pasa por decenas de vueltas: que no se duplique en cada una (la referencia
            // también se quedaría sin memoria). Sobre ella, la pieza lee P sin agregarla entera.
            8 if global => format!("{}[0]", p),
            8 => p.to_string(),
            9 => format!("length({})", p),
            10 if global => "other[0]".to_string(),
            10 => "other".to_string(),
            11 => "\"\"".to_string(),
            12 => format!("pick({})", i),
            13 => format!("({} + 1)", i),
            14 => "rebind()".to_string(),
            _ => "grow()".to_string(),
        }
    }

    /// `set p to p + …` con 1 a 4 piezas; a veces una que, desde la tercera vuelta, no se suma.
    fn chain(&mut self, p: &str, i: &str, global: bool, ind: &str) -> String {
        let k = 1 + self.rng.below(4);
        let bad = if self.rng.chance(6) { Some(self.rng.below(k)) } else { None };
        let mut s = format!("{}set {} to {}", ind, p, p);
        for j in 0..k {
            let x = if bad == Some(j) { format!("bad({})", i) } else { self.piece(p, i, global) };
            s += &format!(" + {}", x);
        }
        s + "\n"
    }

    /// Una sentencia de un cuerpo de vuelta sobre `p`.
    fn stmt(&mut self, p: &str, i: &str, global: bool, ind: &str, snaps: &mut Vec<String>) -> String {
        match self.rng.below(10) {
            0 => {
                let name = format!("snap{}", snaps.len());
                snaps.push(name.clone());
                format!("{}set {} to {}\n", ind, name, p)
            }
            1 => format!("{}set other to {} + \"|\"\n", ind, p),
            2 => format!("{}print(length({}), steps())\n", ind, p),
            _ => self.chain(p, i, global, ind),
        }
    }

    fn program(&mut self) -> String {
        let mut s = String::from(
            "let s be \"s\"\nlet other be \"o\"\n\
             task rebind()\n    set s to \"re\"\n    give \"!\"\n\
             task grow()\n    set s to s + \"+\"\n    give \".\"\n\
             task pick(i)\n    when i % 2 == 0\n        give \"p\"\n    give i\n\
             task bad(i)\n    when i < 2\n        give \"b\"\n",
        );
        s += match self.rng.below(4) {
            0 => "    give nothing\n",
            1 => "    give [i]\n",
            2 => "    give {\"k\": i}\n",
            _ => "    give 7\n",
        };
        let mut snaps: Vec<String> = Vec::new();
        let mut body = String::new();
        // La global, en una vuelta del nivel superior.
        body += "each i in range(0, 4)\n";
        for _ in 0..3 {
            body += &self.stmt("s", "i", true, "    ", &mut snaps);
        }
        // Una variable de la vuelta (ventana), que empieza en línea o en el montón.
        body += "each j in range(0, 3)\n";
        body += if self.rng.chance(50) { "    let w be \"w\"\n" } else { "    let w be \"una base que no entra en línea\"\n" };
        body += "    each i in range(0, 4)\n";
        for _ in 0..2 {
            body += &self.stmt("w", "i", false, "        ", &mut snaps);
        }
        body += "    set s to s + w\n";
        // Un parámetro de una task que compila.
        body += "task t(p, n)\n    each i in range(0, n)\n";
        for _ in 0..2 {
            body += &self.stmt("p", "i", false, "        ", &mut snaps);
        }
        body += "    give p\n";
        body += "let e1 be t(\"a\", 1)\nlet e2 be t(e1, 3)\nlet e3 be t(s, 4)\n";
        // La global escrita desde una task.
        body += "task g(n)\n    each i in range(0, n)\n";
        for _ in 0..2 {
            body += &self.stmt("s", "i", true, "        ", &mut snaps);
        }
        body += "    give n\n";
        body += "each q in range(0, 3)\n    g(q + 1)\n";
        // Un local de un frame que ve una closure.
        body += "task h(n)\n    let loc be \"l\"\n    let peek be () => length(loc)\n    each i in range(0, n)\n";
        for _ in 0..2 {
            body += &self.stmt("loc", "i", false, "        ", &mut snaps);
        }
        body += "    give [loc, peek()]\n";
        body += "let h1 be h(1)\nlet h2 be h(4)\n";
        // P en un hueco: un `let` en una rama que no corrió (se escribe la global).
        body += "task hz(flag, n)\n    when flag\n        let s be \"local\"\n    each i in range(0, n)\n";
        for _ in 0..2 {
            body += &self.stmt("s", "i", true, "        ", &mut snaps);
        }
        body += "    give s\n";
        body += "let z1 be hz(false, 3)\nlet z2 be hz(true, 3)\nlet z3 be hz(false, 2)\nprint(z1, z2, z3)\n";
        // Números y texto por el mismo sitio.
        if self.rng.chance(50) {
            body += "task mix(v, n)\n    each i in range(0, n)\n        set v to v + i + 1\n    give v\n";
            body += "print(mix(0, 4), mix(\"m\", 4), mix(1, 3), mix(\"n\", 3))\n";
        }
        for n in &snaps {
            s += &format!("let {} be \"\"\n", n);
        }
        s += &body;
        s += &format!("print(s, other, e1, e2, e3, h1, h2{}{})\n", if snaps.is_empty() { "" } else { ", " }, snaps.join(", "));
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
    eprintln!("text_chain_fuzz: {} programas ({} terminan en error)", count, errors);
    assert!(failures.is_empty(), "{} programa(s) dan distinto:\n\n{}", failures.len(), failures.join("\n\n"));
    // Que el generador no sea todo errores (cada error corta el programa ahí), ni ninguno.
    assert!(errors < count / 2, "demasiados programas terminan en error: {}", errors);
    assert!(errors > 0 || count < 50, "ningún programa llegó a una pieza que no se suma");
}

/// Una pieza `secret` a mitad de una cadena ya en modo texto: la única pieza que no se suma y no es
/// error, así que es donde se ve el intermedio (P vieja + las piezas hasta ahí) que arma la VM. El
/// `secret` se fabrica por el borde del core (`as_secret` vive en el stdlib).
#[test]
fn a_secret_piece_gets_the_reference_intermediate() {
    use synsema_core::interpreter::{env_get, Interpreter};
    use synsema_core::parser::parse_source;
    use synsema_core::types::{syn_secret, SynValue};
    let src = "let s be \"base que no entra en línea-\"\n\
               task pick(i)\n    when i < 3\n        give \"p\"\n    give k\n\
               each i in range(0, 5)\n    set s to s + text(i) + \",\" + pick(i) + \".\"\n    print(steps())\n";
    let program = parse_source(src, "<secret>").expect("parse");
    let run = |reference: bool| {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        set_reference_mode(reference);
        let mut interp = Interpreter::new();
        interp.set_global("k", syn_secret("K", "<clave>"));
        let r = interp.execute(&program);
        set_reference_mode(false);
        assert!(r.is_ok(), "falló");
        let s = match env_get(&interp.global_env, "s") {
            Some(SynValue::Secret(x)) => x.expose().to_string(),
            other => panic!("s no es secret: {:?}", other.map(|v| v.type_name())),
        };
        (s, interp.output.clone())
    };
    let (reference, fast) = (run(true), run(false));
    assert_eq!(reference, fast);
    assert!(reference.0.starts_with("base que no entra en línea-0,p.1,p.2,p.3,<clave>."), "{}", reference.0);
}

#[test]
fn text_chains_match_the_reference_on_generated_programs() {
    check(0x7e_f46c_01, 200);
}

#[test]
#[ignore]
fn text_chains_match_the_reference_on_many_generated_programs() {
    check(0x7e_f46c_0000_0002, 3000);
}

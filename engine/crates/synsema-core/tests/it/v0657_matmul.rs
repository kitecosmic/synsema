//! v0.6.57: `matmul` con hilos sin perder los bits, matriz × vector en el orden escrito y `dot` como
//! reducción de 16 carriles (specs/v0.6.57-migas.md §3b).
//!
//! El modelo de referencia usa `libm::fma` (Rust puro, correcto en toda plataforma): nunca `mul_add`,
//! que con MinGW llama a una `fma()` incorrecta.

use synsema_core::interpreter::Control;
use synsema_core::matkernel::{self, dot_f32, dot_f64, matmul_rm};

// ── modelo ────────────────────────────────────────────────────────────────────────────────────────

/// El orden escrito: por elemento, `k` en bloques de 512; cada bloque una cadena de FMA desde `-0.0`
/// con `k` creciente; los bloques se suman en orden; `k = 0` da `+0`.
fn model_f64(a: &[f64], b: &[f64], m: usize, k: usize, n: usize) -> Vec<f64> {
    let mut c = vec![0.0f64; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut out = 0.0f64;
            let mut k0 = 0;
            while k0 < k {
                let k1 = (k0 + 512).min(k);
                let mut acc = -0.0f64;
                for kk in k0..k1 {
                    acc = libm::fma(a[i * k + kk], b[kk * n + j], acc);
                }
                out = if k0 == 0 { acc } else { out + acc };
                k0 = k1;
            }
            c[i * n + j] = out;
        }
    }
    c
}

fn model_f32(a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32> {
    let mut c = vec![0.0f32; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut out = 0.0f32;
            let mut k0 = 0;
            while k0 < k {
                let k1 = (k0 + 512).min(k);
                let mut acc = -0.0f32;
                for kk in k0..k1 {
                    acc = libm::fmaf(a[i * k + kk], b[kk * n + j], acc);
                }
                out = if k0 == 0 { acc } else { out + acc };
                k0 = k1;
            }
            c[i * n + j] = out;
        }
    }
    c
}

/// Números al azar reproducibles (xorshift64*), con negativos, ceros con signo y escalas mezcladas:
/// el orden de las sumas se nota en los últimos bits.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn f64(&mut self) -> f64 {
        let r = self.next();
        match r % 17 {
            0 => 0.0,
            1 => -0.0,
            _ => {
                let u = (r >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0;
                u * [1.0, 1e3, 1e-3, 7.5][(r >> 5) as usize % 4]
            }
        }
    }
    fn vec64(&mut self, n: usize) -> Vec<f64> {
        (0..n).map(|_| self.f64()).collect()
    }
    fn vec32(&mut self, n: usize) -> Vec<f32> {
        (0..n).map(|_| self.f64() as f32).collect()
    }
}

fn bits64(v: &[f64]) -> Vec<u64> {
    v.iter().map(|x| x.to_bits()).collect()
}
fn bits32(v: &[f32]) -> Vec<u32> {
    v.iter().map(|x| x.to_bits()).collect()
}

/// FNV-1a de 64 bits sobre los bits del resultado (la huella de un `matmul` fijo).
fn fnv(bits: impl Iterator<Item = u64>) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in bits {
        for byte in b.to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// ¿Aplica la promesa bit a bit acá? (x86-64 con AVX2+FMA o AVX-512, decisión (b).)
fn promise() -> bool {
    cfg!(target_arch = "x86_64") && matches!(matkernel::isa(), "avx2+fma" | "avx512f+fma")
}

/// Formas que pasan por los tres caminos (vector × matriz, matriz × vector, faer), con `k` de un
/// bloque, justo pasado el bloque y de varios bloques, y las chicas de nano-gemm.
const SHAPES: &[(usize, usize, usize)] = &[
    (1, 1, 1),
    (2, 1, 3),
    (3, 4, 5),
    (1, 7, 9),
    (9, 7, 1),
    (1, 513, 33),
    (33, 513, 1),
    (1, 1300, 40),
    (40, 1300, 1),
    (3, 513, 2),
    (16, 16, 16),
    (17, 600, 23),
    (64, 1025, 70),
    (128, 2048, 96),
];

// ── ítem 1/2/6: matmul sigue el modelo (dentro de la promesa) ───────────────────────────────────────

#[test]
fn matmul_follows_the_written_order_f64() {
    if !promise() {
        eprintln!("fuera de la promesa bit a bit ({}): sólo se mide la invariancia de hilos", matkernel::isa());
        return;
    }
    let mut r = Rng(0x5eed_0657);
    for &(m, k, n) in SHAPES {
        let (a, b) = (r.vec64(m * k), r.vec64(k * n));
        let want = bits64(&model_f64(&a, &b, m, k, n));
        for t in [1, 4] {
            let got = bits64(&matmul_rm(&a, &b, m, k, n, t));
            assert_eq!(got, want, "f64 {}×{}×{} con {} hilos no sigue el orden escrito", m, k, n, t);
        }
    }
}

#[test]
fn matmul_follows_the_written_order_f32() {
    if !promise() {
        return;
    }
    let mut r = Rng(0x5eed_0f32);
    for &(m, k, n) in SHAPES {
        let (a, b) = (r.vec32(m * k), r.vec32(k * n));
        let want = bits32(&model_f32(&a, &b, m, k, n));
        for t in [1, 4] {
            let got = bits32(&matmul_rm(&a, &b, m, k, n, t));
            assert_eq!(got, want, "f32 {}×{}×{} con {} hilos no sigue el orden escrito", m, k, n, t);
        }
    }
}

// ── ítem 1: los hilos no cambian los bits (en toda plataforma) ──────────────────────────────────────

#[test]
fn matmul_threads_do_not_change_the_bits() {
    // Formas que pasan el umbral de reparto en los dos tipos (`f32`: 2^24 por hilo), con k > 512.
    let mut r = Rng(0x0657_0001);
    for &(m, k, n) in &[(512usize, 512usize, 512usize), (300, 700, 200), (200, 300, 700), (200, 1030, 300)] {
        let (a, b) = (r.vec64(m * k), r.vec64(k * n));
        let one = bits64(&matmul_rm(&a, &b, m, k, n, 1));
        for t in [2, 3, 12] {
            assert_eq!(bits64(&matmul_rm(&a, &b, m, k, n, t)), one, "f64 {}×{}×{}: {} hilos ≠ 1", m, k, n, t);
        }
        let (a, b): (Vec<f32>, Vec<f32>) = (a.iter().map(|&x| x as f32).collect(), b.iter().map(|&x| x as f32).collect());
        let one = bits32(&matmul_rm(&a, &b, m, k, n, 1));
        for t in [2, 3, 12] {
            assert_eq!(bits32(&matmul_rm(&a, &b, m, k, n, t)), one, "f32 {}×{}×{}: {} hilos ≠ 1", m, k, n, t);
        }
    }
}

/// La huella de un 512×512 fijo, con 1 hilo y con todos. Dentro de la promesa también es una
/// constante: si faer (o el modelo) cambia de orden, este número cambia.
#[test]
fn matmul_512_fingerprint() {
    eprintln!(
        "matmul: arch {}, isa {}, bitwise promise {}",
        std::env::consts::ARCH,
        matkernel::isa(),
        if promise() { "checked" } else { "does not apply (only threads)" }
    );
    let mut r = Rng(0x0657_0512);
    let (a, b) = (r.vec64(512 * 512), r.vec64(512 * 512));
    let one = fnv(matmul_rm(&a, &b, 512, 512, 512, 1).iter().map(|x| x.to_bits()));
    let all = fnv(matmul_rm(&a, &b, 512, 512, 512, matkernel::logical_cores().max(2)).iter().map(|x| x.to_bits()));
    assert_eq!(one, all, "512×512: la huella cambia con los hilos");
    if promise() {
        let model = fnv(model_f64(&a, &b, 512, 512, 512).iter().map(|x| x.to_bits()));
        assert_eq!(one, model, "512×512: la huella no es la del orden escrito");
        assert_eq!(one, GOLDEN_512, "512×512: la huella cambió (¿faer cambió de orden?): {:#018x}", one);
    }
}
const GOLDEN_512: u64 = 0x9c24_8ec8_c167_aa64;

// ── ítem 2: el cero con signo y k = 0 ───────────────────────────────────────────────────────────────

#[test]
fn matmul_signed_zero_and_empty_k() {
    // k = 1 con A = −0: el bloque arranca en −0, así que el resultado es −0 en los tres caminos.
    for &(m, n) in &[(1usize, 3usize), (3, 1), (2, 2), (5, 7)] {
        let a = vec![-0.0f64; m];
        let b = vec![3.0f64; n];
        for x in matmul_rm(&a, &b, m, 1, n, 1) {
            assert!(x == 0.0 && x.is_sign_negative(), "{}×1×{}: −0·3 tiene que dar −0, dio {:?}", m, n, x);
        }
        let a32 = vec![-0.0f32; m];
        let b32 = vec![3.0f32; n];
        for x in matmul_rm(&a32, &b32, m, 1, n, 1) {
            assert!(x == 0.0 && x.is_sign_negative(), "f32 {}×1×{}: −0·3 tiene que dar −0, dio {:?}", m, n, x);
        }
    }
    // −0 + −0 en un bloque y +0 en el siguiente: −0 + +0 = +0 al sumar los bloques.
    let mut a = vec![-0.0f64; 513];
    a[512] = 0.0;
    let b = vec![1.0f64; 513];
    let y = matmul_rm(&a, &b, 1, 513, 1, 1)[0];
    assert!(y == 0.0 && y.is_sign_positive(), "dos bloques −0 y +0 suman +0, dio {:?}", y);
    // k = 0: +0.
    for x in matmul_rm::<f64>(&[], &[], 2, 0, 3, 1) {
        assert!(x == 0.0 && x.is_sign_positive());
    }
}

/// Matriz × vector con k > 512 sin depender de la FMA: valores donde el orden de bloques se ve en
/// la suma (el bloque 2 se suma aparte, no sigue la cadena del bloque 1).
#[test]
fn matvec_blocks_of_512() {
    let k = 1025;
    let mut x = vec![0.0f64; k];
    x[0] = 1e16;
    x[511] = 1.0; // en el bloque 1, después de 1e16: se pierde (1e16 + 1 = 1e16)
    x[512] = 1.0; // el bloque 2 arranca solo: vale 1 + 1 = 2
    x[513] = 1.0;
    x[1024] = -1e16; // bloque 3
    let ones = vec![1.0f64; k];
    // Bloques: 1e16, 2, −1e16 → (1e16 + 2) − 1e16 = 2. Una sola cadena daría 0.
    assert_eq!(matmul_rm(&ones, &x, 1, k, 1, 1)[0], 2.0, "vector × vector (k > 512)");
    assert_eq!(matmul_rm(&x, &ones, 1, k, 1, 1)[0], 2.0);
    // m = 1 (vector × matriz) y n = 1 (matriz × vector) con dos columnas/filas iguales.
    let b2: Vec<f64> = x.iter().flat_map(|&v| [v, v]).collect(); // k×2
    assert_eq!(matmul_rm(&ones, &b2, 1, k, 2, 1), vec![2.0, 2.0], "vector × matriz");
    let a2: Vec<f64> = x.iter().chain(x.iter()).copied().collect(); // 2×k
    assert_eq!(matmul_rm(&a2, &ones, 2, k, 1, 1), vec![2.0, 2.0], "matriz × vector");
}

// ── ítem 3: dot en 16 carriles ──────────────────────────────────────────────────────────────────────

#[test]
fn dot_sixteen_lanes() {
    // Carril 0: 1e16 y −1e16 se cancelan; carril 1: 1. Una suma en orden daría 0 (1e16 + 1 = 1e16).
    let mut x = vec![0.0f64; 32];
    x[0] = 1e16;
    x[1] = 1.0;
    x[16] = -1e16;
    let ones = vec![1.0f64; 32];
    assert_eq!(dot_f64(&x, &ones), 1.0, "16 carriles");
    // El árbol: carril 0 + carril 8 primero. 1e16 (c0), −1e16 (c8), 1 (c4): (c0 + c8) + (c4 + c12) = 1;
    // un árbol que empezara por c0 + c1 … o en orden daría otro resultado.
    let mut y = vec![0.0f64; 16];
    y[0] = 1e16;
    y[8] = -1e16;
    y[4] = 1.0;
    assert_eq!(dot_f64(&y, &ones[..16]), 1.0, "el árbol +8, +4, +2, +1");
    let mut y2 = vec![0.0f64; 16];
    y2[0] = 1e16;
    y2[1] = 1.0;
    y2[9] = -1e16; // c1 + c9 primero: 1 − 1e16 = −1e16; después c0 + c1 = 0
    assert_eq!(dot_f64(&y2, &ones[..16]), 0.0, "el árbol suma c1 + c9 antes que c0 + c1");
    // La cola va después del árbol, en orden: 1e16 (c0) + 1 (c1) = 1e16 en el árbol, después −1e16.
    let mut z = vec![0.0f64; 33];
    z[0] = 1e16;
    z[1] = 1.0;
    z[32] = -1e16;
    assert_eq!(dot_f64(&z, &vec![1.0; 33]), 0.0, "la cola se suma después del árbol");
    // Vacío: +0.
    let e = dot_f64(&[], &[]);
    assert!(e == 0.0 && e.is_sign_positive());
    // Sin FMA: (1 + 2^-30)·(1 − 2^-30) = 1 − 2^-60, que el producto redondea a 1.
    // t = −1; después t + p·q: sin FMA, −1 + 1 = 0; con FMA, fma(p, q, −1) = −2^-60.
    let p = 1.0 + f64::powi(2.0, -30);
    let q = 1.0 - f64::powi(2.0, -30);
    assert_eq!(dot_f64(&[-1.0, p], &[1.0, q]), 0.0, "dot multiplica y suma por separado (sin FMA)");
    // Lo mismo dentro de un carril: el carril 0 suma −1 (x[0]) y después p·q (x[16]).
    let mut u = vec![0.0f64; 32];
    let mut v = vec![0.0f64; 32];
    (u[0], v[0], u[16], v[16]) = (-1.0, 1.0, p, q);
    assert_eq!(dot_f64(&u, &v), 0.0, "sin FMA también en los carriles");
    // 16 carriles, no 8: (x0 + x16) + (x8 + x24) = 1; con 8 carriles ((x0 + x8) + x16) + x24 = 0.
    let mut w = vec![0.0f64; 32];
    (w[0], w[8], w[16]) = (1e16, 1.0, -1e16);
    assert_eq!(dot_f64(&w, &ones), 1.0, "16 carriles, no 8");
}

#[test]
fn dot_f32_accumulates_in_f64_and_rounds_once() {
    // En f32: 16777216 + 1 = 16777216 dos veces. En f64: 16777218, exacto en f32.
    let x = [16_777_216.0f32, 1.0, 1.0];
    let ones = [1.0f32; 3];
    assert_eq!(dot_f32(&x, &ones) as f32, 16_777_218.0);
    // El mismo orden de 16 carriles.
    let mut a = vec![0.0f32; 32];
    a[0] = 1e30;
    a[1] = 1.0;
    a[16] = -1e30;
    assert_eq!(dot_f32(&a, &vec![1.0f32; 32]), 1.0);
}

/// La huella de `dot`, sin condición de plataforma: la promesa de `dot` vale en todas (x86, ARM,
/// macOS, wasm), así que esta constante es la misma en toda la matriz del CI. Si un compilador
/// contrae `acc + x*y` en una FMA, o cambian los carriles o el árbol, se pone rojo.
#[test]
fn dot_fingerprint() {
    let mut rng = Rng(0x5eed_d07_0657);
    let mut bits = Vec::new();
    for n in [0usize, 1, 15, 16, 17, 31, 1000, 4099] {
        let (a, b) = (rng.vec64(n), rng.vec64(n));
        bits.push(dot_f64(&a, &b).to_bits());
        let (a, b) = (rng.vec32(n), rng.vec32(n));
        bits.push(dot_f32(&a, &b).to_bits());
    }
    let h = fnv(bits.into_iter());
    eprintln!("dot_fingerprint en {} {}: {:#018x}", std::env::consts::ARCH, matkernel::isa(), h);
    assert_eq!(h, GOLDEN_DOT, "dot: la huella cambió: {:#018x}", h);
}
const GOLDEN_DOT: u64 = 0x9d21_cc52_cd7d_96fe;

/// Desde el lenguaje: `dot` en `f64` y `f32` (redondeo único), vacío.
#[test]
fn dot_from_the_language() {
    let run = |src: &str| -> String {
        use synsema_core::interpreter::Interpreter;
        let program = synsema_core::parser::parse_source(src, "<v0657>").unwrap();
        let mut interp = Interpreter::new();
        match interp.execute(&program) {
            Ok(_) => interp.output.join("\n"),
            Err(Control::Error(e)) => format!("ERR: {}", e.message),
            Err(_) => "otro control".to_string(),
        }
    };
    // v0.6.56 sumaba en orden y daba 0.0.
    let mut l = vec!["0"; 32];
    l[0] = "1e16";
    l[1] = "1.0";
    l[16] = "-1e16";
    assert_eq!(run(&format!("print(dot(array([{}]), ones(32)))", l.join(", "))), "1.0");
    assert_eq!(run("print(dot(array([]), array([])))"), "0.0");
    assert_eq!(
        run("print(dot(array([16777216.0, 1.0, 1.0], dtype = \"f32\"), array([1.0, 1.0, 1.0], dtype = \"f32\")))"),
        "16777218.0"
    );
}

// ── ítem 5: el tope de hilos ────────────────────────────────────────────────────────────────────────

#[test]
fn thread_cap_local_beats_process() {
    let process = matkernel::process_thread_cap();
    assert!(process >= 1);
    std::thread::spawn(move || {
        assert_eq!(matkernel::thread_cap(), process, "un hilo nuevo arranca con el tope del proceso");
        matkernel::set_local_thread_cap(3);
        assert_eq!(matkernel::thread_cap(), 3);
        assert_eq!(matkernel::process_thread_cap(), process, "el tope local no toca el del proceso");
        matkernel::set_local_thread_cap(0);
        assert_eq!(matkernel::thread_cap(), 1, "mínimo 1");
    })
    .join()
    .unwrap();
}

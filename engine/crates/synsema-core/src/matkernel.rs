//! v0.6.57: `matmul` y `dot` con un orden escrito (specs/v0.6.57-migas.md §3b).
//!
//! **El orden de `matmul`** (el que sigue faer en x86-64 con AVX2+FMA o AVX-512, medido en la fase 0):
//! por elemento `C[i][j]`, `k` en bloques de 512; cada bloque es una cadena de FMA que arranca en
//! `-0.0` (`acc = fma(a[i][k], b[k][j], acc)`, `k` creciente) y los bloques se suman en orden
//! (`c = b0; c = c + b1; …`). Con `k = 0`, `+0`.
//! - Matriz × matriz (m, n > 1): faer con `Par::Seq` sobre vistas sin copia. Varios hilos se reparten
//!   **mosaicos de la salida**, nunca la suma: los bits no dependen de cuántos hilos haya.
//! - Matriz × vector y vector × matriz (m = 1 o n = 1): núcleo propio, porque faer usa ahí otro orden.
//!   La FMA viene de la instrucción: en x86-64 con AVX2+FMA (detectado en tiempo de ejecución, por
//!   `pulp`, sin `unsafe` acá) y en aarch64 (siempre la tiene). Donde no hay FMA por instrucción se usa
//!   `a*b + c`: **nunca `mul_add` sin la instrucción** (con MinGW llama a una `fma()` incorrecta).
//!   La promesa bit a bit vale sólo en x86-64 con AVX2+FMA o AVX-512 (decisión (b) de Joel).
//!
//! **El orden de `dot`** (una reducción, como `sum`): 16 acumuladores (`acc[i mod 16] += x[i]·y[i]`,
//! mul + add sin FMA), un árbol fijo (`acc[l] += acc[l + 8]`, `+4`, `+2`, `+1`) y la cola en orden.
//! Sin FMA, así que da los mismos bits en toda plataforma.
use faer::linalg::matmul::matmul as faer_matmul;
use faer::{Accum, MatMut, MatRef, Par};
use std::sync::atomic::{AtomicUsize, Ordering};

/// El bloque de `k` del orden escrito.
pub const KC: usize = 512;

/// Un tipo de elemento de `matmul`: `f64` o `f32`.
pub trait Elem: Copy + Send + Sync + 'static + core::ops::Add<Output = Self> + core::ops::Mul<Output = Self> {
    const ZERO: Self;
    const NEG_ZERO: Self;
    /// Trabajo mínimo (m·k·n) por hilo para repartir (ver `MIN_WORK_PER_THREAD`).
    const MIN_WORK: usize;
    /// `fma(a, b, c)` con `mul_add`. Sólo en aarch64, que siempre tiene la instrucción (ver `vecmat`).
    fn fused(a: Self, b: Self, c: Self) -> Self;
    /// faer `Par::Seq`, `dst = lhs · rhs`.
    fn mm(dst: MatMut<'_, Self>, lhs: MatRef<'_, Self>, rhs: MatRef<'_, Self>);
    /// `acc[j] = fma(x, row[j], acc[j])` con las instrucciones FMA de x86 (`_mm256_fmadd_*` por pulp).
    /// Los intrínsecos llevan su propio `target_feature`: dan la instrucción aunque no se inlineen
    /// (sin optimizar, `mul_add` dentro de `vectorize` terminaba en la `fma()` de MinGW).
    #[cfg(target_arch = "x86_64")]
    fn fma_row_v3(simd: pulp::x86::V3, x: Self, row: &[Self], acc: &mut [Self]);
}

macro_rules! impl_elem {
    ($t:ty, $row:ident, $min:expr) => {
        impl Elem for $t {
            const ZERO: Self = 0.0;
            const NEG_ZERO: Self = -0.0;
            const MIN_WORK: usize = $min;
            #[inline(always)]
            fn fused(a: Self, b: Self, c: Self) -> Self {
                a.mul_add(b, c)
            }
            fn mm(dst: MatMut<'_, Self>, lhs: MatRef<'_, Self>, rhs: MatRef<'_, Self>) {
                faer_matmul(dst, Accum::Replace, lhs, rhs, 1.0 as $t, Par::Seq);
            }
            #[cfg(target_arch = "x86_64")]
            #[inline(always)]
            fn fma_row_v3(simd: pulp::x86::V3, x: Self, row: &[Self], acc: &mut [Self]) {
                $row(simd, x, row, acc)
            }
        }
    };
}
impl_elem!(f64, fma_row_f64, MIN_WORK_PER_THREAD);
impl_elem!(f32, fma_row_f32, 4 * MIN_WORK_PER_THREAD);

#[cfg(target_arch = "x86_64")]
fn fma_row_f64(simd: pulp::x86::V3, x: f64, row: &[f64], acc: &mut [f64]) {
    use pulp::{f64x2, f64x4};
    let xs = simd.splat_f64x4(x);
    let mut ac = acc.chunks_exact_mut(4);
    let mut rc = row.chunks_exact(4);
    for (a, r) in (&mut ac).zip(&mut rc) {
        let v = simd.mul_add_f64x4(xs, f64x4(r[0], r[1], r[2], r[3]), f64x4(a[0], a[1], a[2], a[3]));
        a.copy_from_slice(&[v.0, v.1, v.2, v.3]);
    }
    for (a, &r) in ac.into_remainder().iter_mut().zip(rc.remainder()) {
        *a = simd.mul_add_f64x2(f64x2(x, 0.0), f64x2(r, 0.0), f64x2(*a, 0.0)).0;
    }
}

#[cfg(target_arch = "x86_64")]
fn fma_row_f32(simd: pulp::x86::V3, x: f32, row: &[f32], acc: &mut [f32]) {
    use pulp::{f32x4, f32x8};
    let xs = simd.splat_f32x8(x);
    let mut ac = acc.chunks_exact_mut(8);
    let mut rc = row.chunks_exact(8);
    for (a, r) in (&mut ac).zip(&mut rc) {
        let v = simd.mul_add_f32x8(
            xs,
            f32x8(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]),
            f32x8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]),
        );
        a.copy_from_slice(&[v.0, v.1, v.2, v.3, v.4, v.5, v.6, v.7]);
    }
    for (a, &r) in ac.into_remainder().iter_mut().zip(rc.remainder()) {
        *a = simd.mul_add_f32x4(f32x4(x, 0.0, 0.0, 0.0), f32x4(r, 0.0, 0.0, 0.0), f32x4(*a, 0.0, 0.0, 0.0)).0;
    }
}

// =========================================================
// Hilos
// =========================================================

/// Knobs del proceso que lee este módulo (lista canónica: el test anti-rot del CLI la cruza con
/// el `.env.example` de `init`).
pub const COMPUTE_ENV_VARS: &[&str] = &["SYNSEMA_THREADS"];

/// El tope que fija el host cuando `SYNSEMA_THREADS` no está (0 = ninguno): `serve` reparte los
/// núcleos entre sus workers.
static HOST_CAP: AtomicUsize = AtomicUsize::new(0);
static ENV_CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

std::thread_local! {
    /// El tope de este hilo (0 = el del proceso). Lo fija un worker de `parallel_map`.
    static LOCAL_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `SYNSEMA_THREADS` del entorno del proceso, leído una vez (0 = no está). Un valor que no es un
/// entero >= 1 se avisa por stderr una vez y se ignora: no frena el programa por un knob de
/// rendimiento, pero tampoco calla el error.
fn env_cap() -> usize {
    *ENV_CAP.get_or_init(|| match std::env::var("SYNSEMA_THREADS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<usize>() {
            Ok(n) if n >= 1 => n,
            _ => {
                eprintln!(
                    "warning: SYNSEMA_THREADS={:?} is not a whole number >= 1; ignored (matmul uses the default)",
                    v
                );
                0
            }
        },
        _ => 0,
    })
}

/// El tope por defecto que pone el host (mínimo 1) si `SYNSEMA_THREADS` no está: `serve` lo fija en
/// `núcleos / workers` para que varias requests con `matmul` no se pisen.
pub fn set_host_thread_cap(n: usize) {
    HOST_CAP.store(n.max(1), Ordering::Relaxed);
}

/// Fija el tope de este hilo (mínimo 1), por encima del del proceso: un worker de `parallel_map`
/// reparte el tope entre los workers para no sobrecargar la máquina.
pub fn set_local_thread_cap(n: usize) {
    LOCAL_CAP.with(|c| c.set(n.max(1)));
}

/// El tope del proceso: `SYNSEMA_THREADS`, el del host o los núcleos lógicos (1 en wasm), sin el
/// tope de un worker. Es lo que anota el recibo: el de un worker de `parallel_map` depende de
/// cuántos ítems tiene la lista, que puede ser privada. Los hilos que **usó** un `matmul` no se
/// guardan en ningún lado a propósito: dependen del tamaño de las matrices (`threads_for`).
pub fn process_thread_cap() -> usize {
    if cfg!(target_family = "wasm") {
        return 1;
    }
    let e = env_cap();
    if e != 0 {
        return e;
    }
    let h = HOST_CAP.load(Ordering::Relaxed);
    if h != 0 {
        return h;
    }
    logical_cores()
}

/// Cuántos hilos puede usar `matmul` acá: el tope del hilo, `SYNSEMA_THREADS`, el del host o los
/// núcleos lógicos (1 en wasm).
pub fn thread_cap() -> usize {
    let l = LOCAL_CAP.with(|c| c.get());
    if l != 0 {
        return l;
    }
    process_thread_cap()
}

/// Los núcleos lógicos que ve el motor (1 en wasm).
pub fn logical_cores() -> usize {
    #[cfg(target_family = "wasm")]
    {
        1
    }
    #[cfg(not(target_family = "wasm"))]
    {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    }
}

/// Las instrucciones que usan **los dos** núcleos de `matmul` acá (faer para matriz × matriz, el propio
/// para matriz × vector; si difieren, el menor): `"avx512f+fma"`, `"avx2+fma"`, `"neon+fma"` o
/// `"scalar"`. En x86 exige todo lo de `pulp::x86::V3` (avx2, fma, bmi1/2, lzcnt, f16c, movbe…), más que
/// el `avx2 && fma` de faer: sin V3, matriz × vector es `a*b + c` y ya no hay promesa.
pub fn isa() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if !pulp::x86::V3::is_available() {
            return "scalar";
        }
        if std::arch::is_x86_feature_detected!("avx512f") {
            return "avx512f+fma";
        }
        "avx2+fma"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "neon+fma"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "scalar"
    }
}

/// ¿Aplica acá la promesa bit a bit de `matmul`? x86-64 con AVX2+FMA o AVX-512 (decisión (b)). Sólo de
/// `matmul`: la libm del sistema (`exp`, `tanh`, …) queda afuera.
pub fn matmul_bitwise() -> bool {
    cfg!(target_arch = "x86_64") && matches!(isa(), "avx2+fma" | "avx512f+fma")
}

/// Trabajo mínimo (m·k·n) por hilo para repartir; por debajo, un hilo. Medido (2026-11-05, Ryzen
/// 4600H, Windows): crear un hilo cuesta más que el cálculo hasta ~256³ (96³ con 12 hilos: 9 GFLOP/s
/// contra 55 con uno); con todos los hilos se gana desde ~256³ (59 contra 52). `f32` rinde el doble por
/// hilo y pierde con hilos hasta ~384³ con este umbral: usa 4 veces más.
const MIN_WORK_PER_THREAD: usize = 1 << 22;
/// Ancho mínimo de un mosaico (filas o columnas de la salida).
#[cfg(not(target_family = "wasm"))]
const MIN_TILE: usize = 32;

/// Cuántos hilos usar para un producto m×k×n, con un tope.
#[cfg(not(target_family = "wasm"))]
fn threads_for(m: usize, k: usize, n: usize, cap: usize, min_work: usize) -> usize {
    let work = m.saturating_mul(k).saturating_mul(n);
    let by_work = (work / min_work).max(1);
    let by_tiles = (m.max(n) / MIN_TILE).max(1);
    cap.min(by_work).min(by_tiles).max(1)
}

/// Cuántos hilos usar para `batches` productos de `work_each` (m·k·n) cada uno: cada producto va entero
/// en un hilo. 1 si no conviene repartir.
pub fn batch_threads<T: Elem>(batches: usize, work_each: usize, cap: usize) -> usize {
    if cfg!(target_family = "wasm") || batches < 2 {
        return 1;
    }
    let by_work = (batches.saturating_mul(work_each) / T::MIN_WORK).max(1);
    cap.min(batches).min(by_work).max(1)
}

// =========================================================
// matmul
// =========================================================

/// `C = A · B`, todos row-major (`a` m×k, `b` k×n). Devuelve `C` row-major (m×n). `threads` es el tope.
pub fn matmul_rm<T: Elem>(a: &[T], b: &[T], m: usize, k: usize, n: usize, threads: usize) -> Vec<T> {
    debug_assert_eq!(a.len(), m * k);
    debug_assert_eq!(b.len(), k * n);
    let mut out = vec![T::ZERO; m * n];
    if m == 0 || n == 0 || k == 0 {
        return out;
    }
    if m == 1 {
        vecmat(a, b, n, &mut out);
    } else if n == 1 {
        // y = A·x es yᵀ = xᵀ·Aᵀ: se traspone A (k×m) y es el mismo núcleo.
        let mut at = vec![T::ZERO; k * m];
        for i in 0..m {
            for kk in 0..k {
                at[kk * m + i] = a[i * k + kk];
            }
        }
        vecmat(b, &at, m, &mut out);
    } else {
        gemm(a, b, m, k, n, threads, &mut out);
    }
    out
}

fn gemm<T: Elem>(a: &[T], b: &[T], m: usize, k: usize, n: usize, cap: usize, out: &mut [T]) {
    let fa = MatRef::from_row_major_slice(a, m, k);
    let fb = MatRef::from_row_major_slice(b, k, n);
    #[cfg(target_family = "wasm")]
    let t = {
        let _ = cap;
        1
    };
    #[cfg(not(target_family = "wasm"))]
    let t = threads_for(m, k, n, cap, T::MIN_WORK);
    let fc = MatMut::from_row_major_slice_mut(out, m, n);
    if t <= 1 {
        T::mm(fc, fa, fb);
        return;
    }
    #[cfg(not(target_family = "wasm"))]
    std::thread::scope(|s| {
        // Mosaicos a lo largo de la dimensión más larga de la salida (columnas si es cuadrada).
        if n >= m {
            let w = n.div_ceil(t);
            let mut rest = fc;
            let mut j0 = 0;
            while j0 < n {
                let wj = w.min(n - j0);
                let (tile, r) = rest.split_at_col_mut(wj);
                rest = r;
                let fbj = fb.subcols(j0, wj);
                s.spawn(move || T::mm(tile, fa, fbj));
                j0 += wj;
            }
        } else {
            let h = m.div_ceil(t);
            let mut rest = fc;
            let mut i0 = 0;
            while i0 < m {
                let hi = h.min(m - i0);
                let (tile, r) = rest.split_at_row_mut(hi);
                rest = r;
                let fai = fa.subrows(i0, hi);
                s.spawn(move || T::mm(tile, fai, fb));
                i0 += hi;
            }
        }
    });
}

/// `out[j] = Σ_k x[k]·b[k][j]` en el orden escrito (`b` row-major, k×n).
fn vecmat<T: Elem>(x: &[T], b: &[T], n: usize, out: &mut [T]) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(simd) = pulp::x86::V3::try_new() {
            // `vectorize` deja que el optimizador inline todo con AVX2+FMA; la corrección no depende
            // de eso (`fma_row_v3` usa los intrínsecos).
            return simd.vectorize(|| vecmat_with(x, b, n, out, |xv, row, acc| T::fma_row_v3(simd, xv, row, acc)));
        }
        vecmat_with(x, b, n, out, mul_then_add_row)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 siempre tiene FMA: `mul_add` es la instrucción (o la `fma()` correcta de la libm).
        vecmat_with(x, b, n, out, |xv, row, acc| {
            for (a, &bv) in acc.iter_mut().zip(row) {
                *a = T::fused(xv, bv, *a);
            }
        })
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        vecmat_with(x, b, n, out, mul_then_add_row)
    }
}

/// Sin FMA por instrucción: `a*b + c` (fuera de la promesa). Nunca `mul_add` acá.
#[allow(dead_code)]
#[inline(always)]
fn mul_then_add_row<T: Elem>(xv: T, row: &[T], acc: &mut [T]) {
    for (a, &bv) in acc.iter_mut().zip(row) {
        *a = xv * bv + *a;
    }
}

/// Los bloques de 512 de `k`: cada uno arranca en `-0.0` y `step` le suma una fila; los bloques se
/// suman en orden.
#[inline(always)]
fn vecmat_with<T: Elem>(x: &[T], b: &[T], n: usize, out: &mut [T], step: impl Fn(T, &[T], &mut [T])) {
    let k = x.len();
    let mut acc = vec![T::NEG_ZERO; n];
    let mut k0 = 0;
    while k0 < k {
        let k1 = (k0 + KC).min(k);
        acc.fill(T::NEG_ZERO);
        for kk in k0..k1 {
            step(x[kk], &b[kk * n..kk * n + n], &mut acc);
        }
        if k0 == 0 {
            out.copy_from_slice(&acc);
        } else {
            for (o, &a) in out.iter_mut().zip(acc.iter()) {
                *o = *o + a;
            }
        }
        k0 = k1;
    }
}

// =========================================================
// dot
// =========================================================

const DOT_LANES: usize = 16;

#[inline(always)]
fn dot_tree(mut acc: [f64; DOT_LANES]) -> f64 {
    let mut w = DOT_LANES;
    while w > 1 {
        w /= 2;
        for l in 0..w {
            acc[l] = acc[l] + acc[l + w];
        }
    }
    acc[0]
}

/// `dot` de dos vectores `f64` en el orden escrito (16 carriles, árbol fijo, cola en orden).
pub fn dot_f64(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = [0.0f64; DOT_LANES];
    let (ca, cb) = (a.chunks_exact(DOT_LANES), b.chunks_exact(DOT_LANES));
    let (ra, rb) = (ca.remainder(), cb.remainder());
    for (x, y) in ca.zip(cb) {
        for l in 0..DOT_LANES {
            acc[l] = acc[l] + x[l] * y[l];
        }
    }
    let mut t = dot_tree(acc);
    for (x, y) in ra.iter().zip(rb) {
        t = t + x * y;
    }
    t
}

/// `dot` de dos vectores `f32`: el mismo orden, acumulado en `f64` (el producto de dos `f32` es exacto
/// en `f64`); quien llama redondea una vez a `f32` (F6 de 0.6.56).
pub fn dot_f32(a: &[f32], b: &[f32]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = [0.0f64; DOT_LANES];
    let (ca, cb) = (a.chunks_exact(DOT_LANES), b.chunks_exact(DOT_LANES));
    let (ra, rb) = (ca.remainder(), cb.remainder());
    for (x, y) in ca.zip(cb) {
        for l in 0..DOT_LANES {
            acc[l] = acc[l] + x[l] as f64 * y[l] as f64;
        }
    }
    let mut t = dot_tree(acc);
    for (x, y) in ra.iter().zip(rb) {
        t = t + *x as f64 * *y as f64;
    }
    t
}

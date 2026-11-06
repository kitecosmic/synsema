//! v0.6.57 (ítem 1): `matmul` por lotes reparte los lotes entre hilos (cada producto en un hilo) y
//! da los mismos bits que con un hilo y que cada producto 2-D por separado.

use ndarray::{ArrayD, IxDyn};
use synsema_core::matkernel;
use synsema_core::types::{syn_array, syn_array32, SynValue};

fn data(n: usize, seed: u64) -> Vec<f64> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            ((s >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0) * [1.0, 1e3, 1e-3][(s % 3) as usize]
        })
        .collect()
}

/// Los bits de `matmul` de stdlib en un hilo nuevo con tope `cap` (`SynValue` no es `Send`: los
/// valores se arman adentro).
fn with_cap(cap: usize, args: impl FnOnce() -> (SynValue, SynValue) + Send + 'static) -> Vec<u64> {
    std::thread::spawn(move || {
        matkernel::set_local_thread_cap(cap);
        let (a, b) = args();
        let c = synsema_stdlib::ndarray_ops::matmul(&[a, b]).unwrap_or_else(|_| panic!("matmul por lotes falló"));
        bits(&c)
    })
    .join()
    .unwrap()
}

fn bits(v: &SynValue) -> Vec<u64> {
    let SynValue::Array(a) = v else { panic!("no es un array") };
    match synsema_core::arrays::Num::of(a) {
        synsema_core::arrays::Num::F64 => {
            a.numbers_f64().iter().map(|x| x.to_bits()).collect()
        }
        synsema_core::arrays::Num::F32 => {
            a.numbers_f64().iter().map(|&x| (x as f32).to_bits() as u64).collect()
        }
    }
}

#[test]
fn batched_matmul_threads_do_not_change_the_bits() {
    // 6 lotes de 96×600×160 (9,2 M cada uno: reparte en `f64`, 2^22 por hilo, y en `f32`, 2^24) y el
    // broadcasting [1, …] con [6, …].
    let (bt, m, k, p) = (6usize, 96usize, 600usize, 160usize);
    let a = data(bt * m * k, 0x0657_ba7c);
    let b = data(bt * k * p, 0x0657_0b0b);
    let av = ArrayD::from_shape_vec(IxDyn(&[bt, m, k]), a.clone()).unwrap();
    let bv = ArrayD::from_shape_vec(IxDyn(&[bt, k, p]), b.clone()).unwrap();

    let (a2, b2) = (av.clone(), bv.clone());
    let one = with_cap(1, move || (syn_array(a2), syn_array(b2)));
    let (a2, b2) = (av.clone(), bv.clone());
    let many = with_cap(8, move || (syn_array(a2), syn_array(b2)));
    assert_eq!(one, many, "f64: los lotes con 8 hilos no dan los bits de 1");

    // Cada lote es el producto 2-D del núcleo.
    let mut want = Vec::new();
    for i in 0..bt {
        want.extend(
            matkernel::matmul_rm(&a[i * m * k..(i + 1) * m * k], &b[i * k * p..(i + 1) * k * p], m, k, p, 1)
                .iter()
                .map(|x| x.to_bits()),
        );
    }
    assert_eq!(one, want, "f64: un lote no es el producto 2-D");

    // f32.
    let (a32, b32) = (av.mapv(|x| x as f32), bv.mapv(|x| x as f32));
    let (a2, b2) = (a32.clone(), b32.clone());
    let one32 = with_cap(1, move || (syn_array32(a2), syn_array32(b2)));
    let many32 = with_cap(8, move || (syn_array32(a32), syn_array32(b32)));
    assert_eq!(one32, many32, "f32: los lotes con 8 hilos no dan los bits de 1");

    // Broadcasting: A [1, m, k] con B [6, k, p].
    let a1 = ArrayD::from_shape_vec(IxDyn(&[1, m, k]), a[..m * k].to_vec()).unwrap();
    let (a2, b2) = (a1.clone(), bv.clone());
    let one_b = with_cap(1, move || (syn_array(a2), syn_array(b2)));
    let many_b = with_cap(8, move || (syn_array(a1), syn_array(bv)));
    assert_eq!(one_b, many_b, "broadcasting: los bits cambian con los hilos");
}

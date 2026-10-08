//! Bits (HB2, v0.6.44): `bit_and`, `bit_or`, `bit_xor`, `bit_not`, `shl`, `shr` sobre enteros de
//! 64 bits con signo, y `xor_bytes`. Puros, sin capability; compilan para wasm.
//!
//! Viven en stdlib y no en `synsema-core/src/math.rs` A PROPÓSITO: con LTO y PGO, cualquier código
//! nuevo en el núcleo movía decisiones de inlining en el intérprete caliente que nadie tocó (medido:
//! `fib` +7,5 % de tiempo con las mismas instrucciones; `records` +1,2 % de instrucciones por
//! `LambdaCall::item` fuera del closure de `apply`). Acá el `run` del núcleo queda idéntico.
//!
//! Los enteros de Synsema son de precisión arbitraria, pero un operador de bits sobre un entero
//! infinito no tiene un ancho que respetar (¿cuántos unos tiene `bit_not(0)`?). Se fija el de i64,
//! complemento a dos: lo que esperan los protocolos binarios (CRC, rotaciones, máscaras). Lo que no
//! entra en 64 bits, un corrimiento fuera de 0..=63 o un `shl` que desborda es ERROR, nunca un
//! resultado truncado.

use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{syn_int, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
}

fn arity(args: &[SynValue], n: usize, name: &str) -> Result<(), Control> {
    if args.len() != n {
        return Err(err(format!("{} expects {} argument(s), got {}", name, n, args.len())));
    }
    Ok(())
}

fn num<'a>(args: &'a [SynValue], i: usize, name: &str) -> Result<&'a Number, Control> {
    match arg(args, i)? {
        SynValue::Number(n) => Ok(n),
        other => Err(err(format!("{} expects a number, got {}", name, other.type_name()))),
    }
}

/// Registra los siete builtins (lo llaman `engine.rs` y `synsema-wasm`, junto a los hashes).
pub fn register_bit_builtins(interp: &Interpreter) {
    interp.register_builtin("bit_and", 2, Rc::new(|_i, a, _l| bit_and(a)));
    interp.register_builtin("bit_or", 2, Rc::new(|_i, a, _l| bit_or(a)));
    interp.register_builtin("bit_xor", 2, Rc::new(|_i, a, _l| bit_xor(a)));
    interp.register_builtin("bit_not", 1, Rc::new(|_i, a, _l| bit_not(a)));
    interp.register_builtin("shl", 2, Rc::new(|_i, a, _l| shl(a)));
    interp.register_builtin("shr", 2, Rc::new(|_i, a, _l| shr(a)));
    interp.register_builtin("xor_bytes", 2, Rc::new(|_i, a, _l| xor_bytes(a)));
}

fn i64_arg(args: &[SynValue], i: usize, name: &str) -> Result<i64, Control> {
    let n = num(args, i, name)?;
    let bi = n.as_bigint().ok_or_else(|| err(format!("{} works on integers, got a float", name)))?;
    i64::try_from(&bi).map_err(|_| err(format!("{} works on 64-bit integers (-2^63 .. 2^63-1), got {}", name, bi)))
}

fn shift_arg(args: &[SynValue], name: &str) -> Result<u32, Control> {
    let n = i64_arg(args, 1, name)?;
    if !(0..=63).contains(&n) {
        return Err(err(format!("{}: the shift must be between 0 and 63, got {}", name, n)));
    }
    Ok(n as u32)
}

fn bit_binary(args: &[SynValue], name: &str, f: fn(i64, i64) -> i64) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    Ok(syn_int(f(i64_arg(args, 0, name)?, i64_arg(args, 1, name)?)))
}

pub fn bit_and(args: &[SynValue]) -> Result<SynValue, Control> {
    bit_binary(args, "bit_and", |a, b| a & b)
}
pub fn bit_or(args: &[SynValue]) -> Result<SynValue, Control> {
    bit_binary(args, "bit_or", |a, b| a | b)
}
pub fn bit_xor(args: &[SynValue]) -> Result<SynValue, Control> {
    bit_binary(args, "bit_xor", |a, b| a ^ b)
}
pub fn bit_not(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "bit_not")?;
    Ok(syn_int(!i64_arg(args, 0, "bit_not")?))
}

/// `shl(x, n)` = `x · 2ⁿ`; si el resultado no entra en 64 bits con signo, error (no envuelve).
pub fn shl(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "shl")?;
    let x = i64_arg(args, 0, "shl")?;
    let n = shift_arg(args, "shl")?;
    let r = x.checked_shl(n).filter(|r| (r >> n) == x).ok_or_else(|| err(format!("shl: {} << {} does not fit in a 64-bit integer", x, n)))?;
    Ok(syn_int(r))
}

/// `shr(x, n)` aritmético: conserva el signo (`shr(-8, 1)` = -4), como `x // 2ⁿ`.
pub fn shr(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "shr")?;
    let x = i64_arg(args, 0, "shr")?;
    let n = shift_arg(args, "shr")?;
    Ok(syn_int(x >> n))
}

/// `xor_bytes(a, b)`: XOR byte a byte de dos `bytes` del mismo largo.
pub fn xor_bytes(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "xor_bytes")?;
    let get = |i: usize| -> Result<&synsema_core::types::BytesRef, Control> {
        match arg(args, i)? {
            SynValue::Bytes(b) => Ok(b),
            SynValue::Text(_) => Err(err("xor_bytes works on bytes, got text; convert it first with bytes(text)")),
            other => Err(err(format!("xor_bytes works on bytes, got {}", other.type_name()))),
        }
    };
    let (a, b) = (get(0)?, get(1)?);
    if a.len() != b.len() {
        return Err(err(format!("xor_bytes: the two values must have the same length, got {} and {} bytes", a.len(), b.len())));
    }
    Ok(synsema_core::types::syn_bytes(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect::<Vec<u8>>()))
}

#[cfg(test)]
mod bit_tests {
    use super::*;
    use num_bigint::BigInt;
    use synsema_core::number::Number;
    use synsema_core::types::{syn_bool, syn_float, syn_number, syn_text};

    fn i(v: i64) -> SynValue {
        syn_int(v)
    }
    fn ok(r: Result<SynValue, Control>) -> String {
        r.unwrap_or_else(|_| panic!("expected a value")).to_string()
    }
    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.into_message(),
            _ => panic!("expected an error"),
        }
    }

    #[test]
    fn bit_tables_and_negatives() {
        for (a, b) in [(0b1100i64, 0b1010i64), (0, 0), (-1, 0x0f), (-8, 3), (i64::MIN, -1), (i64::MAX, 1)] {
            assert_eq!(ok(bit_and(&[i(a), i(b)])), (i(a & b)).to_string());
            assert_eq!(ok(bit_or(&[i(a), i(b)])), (i(a | b)).to_string());
            assert_eq!(ok(bit_xor(&[i(a), i(b)])), (i(a ^ b)).to_string());
        }
        assert_eq!(ok(bit_and(&[i(12), i(10)])), (i(8)).to_string());
        assert_eq!(ok(bit_or(&[i(12), i(10)])), (i(14)).to_string());
        assert_eq!(ok(bit_xor(&[i(12), i(10)])), (i(6)).to_string());
        assert_eq!(ok(bit_xor(&[i(0x36), i(0x5c)])), i(0x6a).to_string(), "ipad ^ opad de HMAC");
        assert_eq!(ok(bit_not(&[i(0)])), (i(-1)).to_string());
        assert_eq!(ok(bit_not(&[i(-1)])), (i(0)).to_string());
        assert_eq!(ok(bit_not(&[i(5)])), (i(-6)).to_string());
    }

    #[test]
    fn shifts_and_their_edges() {
        assert_eq!(ok(shl(&[i(1), i(0)])), (i(1)).to_string());
        assert_eq!(ok(shl(&[i(1), i(62)])), (i(1 << 62)).to_string());
        assert_eq!(ok(shl(&[i(-1), i(63)])), (i(i64::MIN)).to_string());
        assert_eq!(ok(shl(&[i(-3), i(2)])), (i(-12)).to_string());
        assert_eq!(ok(shr(&[i(256), i(4)])), (i(16)).to_string());
        assert_eq!(ok(shr(&[i(-8), i(1)])), i(-4).to_string(), "aritmético: conserva el signo");
        assert_eq!(ok(shr(&[i(-1), i(63)])), (i(-1)).to_string());
        assert_eq!(ok(shr(&[i(i64::MAX), i(63)])), (i(0)).to_string());
        // Desplazamientos fuera de 0..=63 y desbordes: error, nunca un valor truncado.
        assert!(msg(shl(&[i(1), i(64)])).contains("between 0 and 63, got 64"));
        assert!(msg(shr(&[i(1), i(64)])).contains("between 0 and 63"));
        assert!(msg(shl(&[i(1), i(-1)])).contains("between 0 and 63, got -1"));
        assert!(msg(shl(&[i(1), i(63)])).contains("does not fit in a 64-bit integer"));
        assert!(msg(shl(&[i(i64::MAX), i(1)])).contains("does not fit"));
    }

    #[test]
    fn bits_refuse_what_is_not_a_64_bit_integer() {
        let big = syn_number(Number::from_bigint(BigInt::from(1u8) << 64));
        assert!(msg(bit_and(&[big, i(1)])).contains("64-bit integers"));
        assert!(msg(bit_xor(&[syn_float(1.5), i(1)])).contains("integers, got a float"));
        assert!(msg(bit_or(&[syn_text("1"), i(1)])).contains("expects a number, got text"));
        assert!(msg(bit_not(&[syn_bool(true)])).contains("expects a number"));
    }

    #[test]
    fn xor_bytes_same_length_only() {
        use synsema_core::types::syn_bytes;
        assert_eq!(ok(xor_bytes(&[syn_bytes(vec![0x36u8; 4]), syn_bytes(vec![0x5cu8, 0, 0xff, 0x36])])), (syn_bytes(vec![0x6au8, 0x36, 0xc9, 0])).to_string());
        assert_eq!(ok(xor_bytes(&[syn_bytes(Vec::<u8>::new()), syn_bytes(Vec::<u8>::new())])), (syn_bytes(Vec::<u8>::new())).to_string());
        assert!(msg(xor_bytes(&[syn_bytes(vec![1u8, 2]), syn_bytes(vec![1u8])])).contains("same length, got 2 and 1 bytes"));
        assert!(msg(xor_bytes(&[syn_text("ab"), syn_bytes(vec![1u8, 2])])).contains("bytes(text)"));
        assert!(msg(xor_bytes(&[i(1), syn_bytes(vec![1u8])])).contains("got number"));
    }
}

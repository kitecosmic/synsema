//! `groth16_verify(vk, proof, public_inputs) → bool`:
//! verificar una prueba Groth16 sobre BN254 (la curva `bn128` de circom/snarkjs; Semaphore,
//! zk-passport y la mayoría de zkTLS) **aceptando los JSON de snarkjs tal cual**. Entrada confiable
//! sin oráculo: el enclave verifica la prueba que trae el payload y punto. Puro, sin capability
//! (no toca red, disco ni reloj: es aritmética sobre datos que ya están en el programa).
//!
//! Contrato:
//! - `vk`: el `verification_key.json` de snarkjs, como map o como texto JSON. Se leen `protocol`
//!   (debe ser `"groth16"`), `curve` (`"bn128"`; se acepta el sinónimo `"bn254"`), `nPublic`,
//!   `vk_alpha_1` (G1), `vk_beta_2`/`vk_gamma_2`/`vk_delta_2` (G2) e `IC` (lista de G1, uno más
//!   que `nPublic`). `vk_alphabeta_12` y cualquier otra clave se IGNORAN (es un precálculo del
//!   verificador de Solidity; acá el pairing se recalcula).
//! - `proof`: el `proof.json` (`pi_a` G1, `pi_b` G2, `pi_c` G1; `protocol`/`curve` se validan si
//!   vienen), como map o texto JSON.
//! - `public_inputs`: la lista de `public.json` — textos decimales o enteros — o ese JSON como texto.
//!   Su largo debe ser exactamente `nPublic`.
//! - Coordenadas en decimal (texto) o entero JSON. G1 proyectivo `[x, y, z]` con `z = "1"`, o el
//!   infinito `["0","1","0"]`; G2 `[[x0, x1], [y0, y1], [z0, z1]]` con `z = ["1","0"]` (o infinito
//!   `[["0","0"],["1","0"],["0","0"]]`). Orden de snarkjs: `c0` (parte "real") primero, `c1`
//!   después = `Fq2::new(c0, c1)` de arkworks. Verificado con los vectores de abajo, no asumido.
//!
//! Falla cerrado: una PRUEBA inválida bien formada devuelve `false`; un FORMATO dudoso es error —
//! protocolo/curva distintos, punto fuera de la curva o del subgrupo (el chequeo de subgrupo en
//! G2 es el que evita las pruebas con puntos de orden pequeño), coordenada no canónica (≥ el
//! módulo del campo), `z` proyectivo distinto de 1, `nPublic` que no calza con `IC` ni con las
//! entradas, escalar ≥ r, número negativo o con decimales.
//!
//! Vectores cruzados con snarkjs 0.7.6 (sin probador propio; ver `fixtures/zk/SOURCE.md`):
//! el `Multiplier` de arkworks-rs/circom-compat (zkey del repo, vk idéntica a la re-exportada, dos
//! pruebas generadas acá) y el `Multiplier(1000)` de iden3/snarkjs `test/groth16` (ptau + setup +
//! prueba generados acá). Deps: `ark-bn254` + `ark-groth16` (puras, `no_std`, sin `parallel`).

use std::rc::Rc;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use num_bigint::BigUint;
use serde_json::Value as J;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{syn_bool, SynValue};

const F: &str = "groth16_verify";

/// Tope de dígitos de una coordenada/escalar: los módulos de BN254 tienen 77 dígitos. Corta
/// antes de parsear un BigUint de megabytes (el parse decimal es cuadrático).
const MAX_DECIMAL_DIGITS: usize = 96;

/// Tope de puntos en `vk.IC` (= nPublic + 1) y de entradas en `public_inputs` (L17 de la
/// auditoría TEE): cada punto se valida en curva y subgrupo y cada entrada pública multiplica un
/// G1, todo dentro de UN paso de fuel — sin tope, una vk de 20 000 puntos cuesta ~1 s por llamada.
/// 2^16 cubre cualquier circuito real (Semaphore, zk-passport, zkTLS usan decenas de entradas);
/// más que eso es un DoS, no una prueba. El tope se comprueba ANTES de parsear un solo punto.
const MAX_IC_POINTS: usize = 65_536;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Entrada: SynValue (map/lista/texto/número) o texto JSON → árbol serde_json
// =========================================================

/// Un map/lista de Synsema al árbol JSON con el que se parsea todo (un solo camino de parseo
/// para el map y para el texto). Los enteros grandes van como texto decimal (serde_json no los
/// representa sin `arbitrary_precision`; para nosotros dígitos son dígitos).
fn syn_to_value(v: &SynValue, what: &str) -> Result<J, Control> {
    Ok(match v {
        SynValue::Nothing => J::Null,
        SynValue::Bool(b) => J::Bool(*b),
        SynValue::Text(s) => J::String(s.to_string()),
        SynValue::Number(Number::Int(i)) => J::Number((*i).into()),
        SynValue::Number(Number::Big(b)) => J::String(b.to_string()),
        SynValue::Number(other) => {
            return Err(err(format!(
                "{}: {} contains a non-integer number ({}); field elements must be whole numbers",
                F, what, other
            )))
        }
        SynValue::List(l) => {
            J::Array(l.borrow().iter().map(|x| syn_to_value(x, what)).collect::<Result<_, _>>()?)
        }
        SynValue::Map(m) => {
            let mut out = serde_json::Map::new();
            for (k, x) in m.borrow().iter() {
                out.insert(k.clone(), syn_to_value(x, what)?);
            }
            J::Object(out)
        }
        other => {
            return Err(err(format!(
                "{}: {} contains a {} value; only maps, lists, text and whole numbers are allowed",
                F,
                what,
                other.type_name()
            )))
        }
    })
}

/// `vk`/`proof`: map de Synsema o texto con el JSON de snarkjs.
fn json_arg(v: Option<&SynValue>, what: &str) -> Result<J, Control> {
    match v {
        Some(SynValue::Text(s)) => serde_json::from_str::<J>(s)
            .map_err(|e| err(format!("{}: {} is not valid JSON: {}", F, what, e))),
        Some(m @ SynValue::Map(_)) => syn_to_value(m, what),
        Some(other) => Err(err(format!(
            "{}: {} must be a map or a JSON text (the snarkjs file as-is), got {}",
            F,
            what,
            other.type_name()
        ))),
        None => Err(err(format!("{}: {} is required", F, what))),
    }
}

// =========================================================
// Decimal → campo → punto (con todos los chequeos de formato)
// =========================================================

/// Entero no negativo en decimal (texto) o entero JSON. Sin signo, sin espacios, sin `0x`,
/// sin exponente: exactamente lo que escribe snarkjs.
fn dec_uint(v: &J, ctx: &str) -> Result<BigUint, Control> {
    let digits: String = match v {
        J::String(s) => s.clone(),
        J::Number(n) => match n.as_u64() {
            Some(u) => u.to_string(),
            None => {
                return Err(err(format!(
                    "{}: {} must be a non-negative whole number (got {})",
                    F, ctx, n
                )))
            }
        },
        other => {
            return Err(err(format!(
                "{}: {} must be a decimal text or a whole number, got {}",
                F,
                ctx,
                json_kind(other)
            )))
        }
    };
    if digits.is_empty() {
        return Err(err(format!("{}: {} is empty", F, ctx)));
    }
    if digits.len() > MAX_DECIMAL_DIGITS {
        return Err(err(format!(
            "{}: {} has {} digits (max {}); BN254 field elements have at most 77",
            F,
            ctx,
            digits.len(),
            MAX_DECIMAL_DIGITS
        )));
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(format!(
            "{}: {} must be a decimal integer in text (only digits), got {:?}",
            F, ctx, digits
        )));
    }
    BigUint::parse_bytes(digits.as_bytes(), 10)
        .ok_or_else(|| err(format!("{}: {} is not a decimal integer", F, ctx)))
}

fn json_kind(v: &J) -> &'static str {
    match v {
        J::Null => "null",
        J::Bool(_) => "a boolean",
        J::Number(_) => "a number",
        J::String(_) => "text",
        J::Array(_) => "a list",
        J::Object(_) => "a map",
    }
}

/// Elemento canónico de un campo primo: `from_bigint` devuelve `None` si el entero es ≥ el
/// módulo (y `try_from` falla si no entra en 256 bits). Ambos casos son "no canónico" → error:
/// un verificador que redujera módulo p aceptaría dos codificaciones del mismo punto.
fn field_element<P: PrimeField>(b: &BigUint, ctx: &str, field: &str) -> Result<P, Control> {
    let too_big = || {
        err(format!(
            "{}: {} is not canonical ({} is >= the {} modulus)",
            F, ctx, b, field
        ))
    };
    let repr = P::BigInt::try_from(b.clone()).map_err(|_| too_big())?;
    P::from_bigint(repr).ok_or_else(too_big)
}

fn fr(v: &J, ctx: &str) -> Result<Fr, Control> {
    field_element::<Fr>(&dec_uint(v, ctx)?, ctx, "scalar field (r)")
}

fn array_of<'a>(v: &'a J, len: usize, ctx: &str, what: &str) -> Result<&'a [J], Control> {
    match v {
        J::Array(a) if a.len() == len => Ok(a.as_slice()),
        J::Array(a) => Err(err(format!(
            "{}: {} must be {} with {} entries, got {}",
            F,
            ctx,
            what,
            len,
            a.len()
        ))),
        other => Err(err(format!("{}: {} must be {}, got {}", F, ctx, what, json_kind(other)))),
    }
}

fn is_zero(b: &BigUint) -> bool {
    *b == BigUint::from(0u8)
}

fn is_one(b: &BigUint) -> bool {
    *b == BigUint::from(1u8)
}

/// Punto G1 en la forma de snarkjs `[x, y, z]`: `z = 1` afín, `[0, 1, 0]` el infinito. Cualquier
/// otro `z` es error (snarkjs siempre normaliza; aceptar proyectivo general abriría dos
/// codificaciones para un mismo punto). Chequea curva y subgrupo (en G1 de BN254 el cofactor es
/// 1, pero el chequeo es explícito para que el contrato no dependa de ese detalle).
fn g1(v: &J, ctx: &str) -> Result<G1Affine, Control> {
    let c = array_of(v, 3, ctx, "a G1 point [x, y, z]")?;
    let x = dec_uint(&c[0], &format!("{}[0] (x)", ctx))?;
    let y = dec_uint(&c[1], &format!("{}[1] (y)", ctx))?;
    let z = dec_uint(&c[2], &format!("{}[2] (z)", ctx))?;
    if is_zero(&z) {
        if is_zero(&x) && is_one(&y) {
            return Ok(G1Affine::identity());
        }
        return Err(err(format!(
            "{}: {} has z = 0 but is not the point at infinity [0, 1, 0]",
            F, ctx
        )));
    }
    if !is_one(&z) {
        return Err(err(format!(
            "{}: {} must be normalized (z = 1 as snarkjs writes it), got z = {}",
            F, ctx, z
        )));
    }
    let p = G1Affine::new_unchecked(
        field_element::<Fq>(&x, &format!("{}[0] (x)", ctx), "base field (q)")?,
        field_element::<Fq>(&y, &format!("{}[1] (y)", ctx), "base field (q)")?,
    );
    if !p.is_on_curve() {
        return Err(err(format!("{}: {} is not on the BN254 G1 curve", F, ctx)));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(err(format!("{}: {} is not in the G1 prime-order subgroup", F, ctx)));
    }
    Ok(p)
}

fn fq2(v: &J, ctx: &str) -> Result<(BigUint, BigUint), Control> {
    let c = array_of(v, 2, ctx, "an Fq2 element [c0, c1]")?;
    Ok((
        dec_uint(&c[0], &format!("{}[0] (c0)", ctx))?,
        dec_uint(&c[1], &format!("{}[1] (c1)", ctx))?,
    ))
}

fn fq2_element((c0, c1): &(BigUint, BigUint), ctx: &str) -> Result<Fq2, Control> {
    Ok(Fq2::new(
        field_element::<Fq>(c0, &format!("{}[0] (c0)", ctx), "base field (q)")?,
        field_element::<Fq>(c1, &format!("{}[1] (c1)", ctx), "base field (q)")?,
    ))
}

/// Punto G2 en la forma de snarkjs `[[x0, x1], [y0, y1], [z0, z1]]`, `c0` primero (= `Fq2::new(c0,
/// c1)`). `z = [1, 0]` afín; `[[0,0],[1,0],[0,0]]` el infinito. El chequeo de subgrupo acá es el
/// que importa: G2 tiene cofactor enorme y un punto de la curva fuera del subgrupo rompe la
/// solidez del pairing.
fn g2(v: &J, ctx: &str) -> Result<G2Affine, Control> {
    let c = array_of(v, 3, ctx, "a G2 point [[x0, x1], [y0, y1], [z0, z1]]")?;
    let x = fq2(&c[0], &format!("{}[0] (x)", ctx))?;
    let y = fq2(&c[1], &format!("{}[1] (y)", ctx))?;
    let z = fq2(&c[2], &format!("{}[2] (z)", ctx))?;
    if is_zero(&z.0) && is_zero(&z.1) {
        if is_zero(&x.0) && is_zero(&x.1) && is_one(&y.0) && is_zero(&y.1) {
            return Ok(G2Affine::identity());
        }
        return Err(err(format!(
            "{}: {} has z = 0 but is not the point at infinity [[0,0],[1,0],[0,0]]",
            F, ctx
        )));
    }
    if !(is_one(&z.0) && is_zero(&z.1)) {
        return Err(err(format!(
            "{}: {} must be normalized (z = [1, 0] as snarkjs writes it), got z = [{}, {}]",
            F, ctx, z.0, z.1
        )));
    }
    let p = G2Affine::new_unchecked(
        fq2_element(&x, &format!("{}[0] (x)", ctx))?,
        fq2_element(&y, &format!("{}[1] (y)", ctx))?,
    );
    if !p.is_on_curve() {
        return Err(err(format!("{}: {} is not on the BN254 G2 curve", F, ctx)));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(err(format!("{}: {} is not in the G2 prime-order subgroup", F, ctx)));
    }
    Ok(p)
}

// =========================================================
// vk / proof / public inputs
// =========================================================

fn object<'a>(v: &'a J, what: &str) -> Result<&'a serde_json::Map<String, J>, Control> {
    match v {
        J::Object(o) => Ok(o),
        other => Err(err(format!(
            "{}: {} must be a map (the snarkjs JSON object), got {}",
            F,
            what,
            json_kind(other)
        ))),
    }
}

fn field<'a>(o: &'a serde_json::Map<String, J>, key: &str, what: &str) -> Result<&'a J, Control> {
    o.get(key)
        .ok_or_else(|| err(format!("{}: {} is missing {:?}", F, what, key)))
}

/// `protocol` debe ser groth16 y `curve` bn128 (o el sinónimo bn254). `required`: en la vk son
/// obligatorios (una vk de PLONK/fflonk tiene otra forma, pero el rechazo debe nombrar la causa);
/// en la prueba se validan sólo si vienen (hay tooling que los recorta).
fn check_protocol_and_curve(o: &serde_json::Map<String, J>, what: &str, required: bool) -> Result<(), Control> {
    match o.get("protocol") {
        Some(J::String(p)) if p == "groth16" => {}
        Some(J::String(p)) => {
            return Err(err(format!(
                "{}: {} is for protocol {:?}; only \"groth16\" is supported (PLONK/fflonk are not)",
                F, what, p
            )))
        }
        Some(other) => {
            return Err(err(format!("{}: {} has a non-text \"protocol\" ({})", F, what, json_kind(other))))
        }
        None if required => return Err(err(format!("{}: {} is missing \"protocol\"", F, what))),
        None => {}
    }
    match o.get("curve") {
        Some(J::String(c)) if c == "bn128" || c == "bn254" => {}
        Some(J::String(c)) => {
            return Err(err(format!(
                "{}: {} is for curve {:?}; only \"bn128\" (BN254) is supported",
                F, what, c
            )))
        }
        Some(other) => {
            return Err(err(format!("{}: {} has a non-text \"curve\" ({})", F, what, json_kind(other))))
        }
        None if required => return Err(err(format!("{}: {} is missing \"curve\"", F, what))),
        None => {}
    }
    Ok(())
}

/// La vk de snarkjs → `VerifyingKey<Bn254>` + `nPublic` (ya cotejado contra `IC`).
fn parse_vk(v: &J) -> Result<(VerifyingKey<Bn254>, usize), Control> {
    const W: &str = "vk";
    let o = object(v, W)?;
    check_protocol_and_curve(o, W, true)?;
    let n_public = match field(o, "nPublic", W)? {
        J::Number(n) => n
            .as_u64()
            .ok_or_else(|| err(format!("{}: vk.nPublic must be a non-negative whole number", F)))?,
        other => {
            return Err(err(format!("{}: vk.nPublic must be a number, got {}", F, json_kind(other))))
        }
    } as usize;
    let ic_json = match field(o, "IC", W)? {
        J::Array(a) => a,
        other => return Err(err(format!("{}: vk.IC must be a list of G1 points, got {}", F, json_kind(other)))),
    };
    if ic_json.len() > MAX_IC_POINTS {
        return Err(err(format!(
            "{}: vk.IC has {} points, more than the {} this release accepts",
            F,
            ic_json.len(),
            MAX_IC_POINTS
        )));
    }
    if n_public >= MAX_IC_POINTS {
        return Err(err(format!(
            "{}: vk.nPublic is {}, more than the {} public inputs this release accepts",
            F,
            n_public,
            MAX_IC_POINTS - 1
        )));
    }
    if ic_json.len() != n_public + 1 {
        return Err(err(format!(
            "{}: vk.nPublic is {} but vk.IC has {} points (it must have nPublic + 1)",
            F,
            n_public,
            ic_json.len()
        )));
    }
    let mut gamma_abc_g1 = Vec::with_capacity(ic_json.len());
    for (i, p) in ic_json.iter().enumerate() {
        gamma_abc_g1.push(g1(p, &format!("vk.IC[{}]", i))?);
    }
    let vk = VerifyingKey::<Bn254> {
        alpha_g1: g1(field(o, "vk_alpha_1", W)?, "vk.vk_alpha_1")?,
        beta_g2: g2(field(o, "vk_beta_2", W)?, "vk.vk_beta_2")?,
        gamma_g2: g2(field(o, "vk_gamma_2", W)?, "vk.vk_gamma_2")?,
        delta_g2: g2(field(o, "vk_delta_2", W)?, "vk.vk_delta_2")?,
        gamma_abc_g1,
    };
    Ok((vk, n_public))
}

fn parse_proof(v: &J) -> Result<Proof<Bn254>, Control> {
    const W: &str = "proof";
    let o = object(v, W)?;
    check_protocol_and_curve(o, W, false)?;
    Ok(Proof::<Bn254> {
        a: g1(field(o, "pi_a", W)?, "proof.pi_a")?,
        b: g2(field(o, "pi_b", W)?, "proof.pi_b")?,
        c: g1(field(o, "pi_c", W)?, "proof.pi_c")?,
    })
}

/// `public_inputs`: lista de textos decimales o enteros, o el `public.json` como texto.
fn parse_public_inputs(v: Option<&SynValue>) -> Result<Vec<Fr>, Control> {
    const W: &str = "public_inputs";
    let j = match v {
        Some(SynValue::Text(s)) => serde_json::from_str::<J>(s)
            .map_err(|e| err(format!("{}: {} as text must be the public.json list, got invalid JSON: {}", F, W, e)))?,
        Some(l @ SynValue::List(_)) => syn_to_value(l, W)?,
        Some(other) => {
            return Err(err(format!(
                "{}: {} must be a list of decimal texts (public.json), got {}",
                F,
                W,
                other.type_name()
            )))
        }
        None => return Err(err(format!("{}: {} is required", F, W))),
    };
    let items = match &j {
        J::Array(a) => a,
        other => return Err(err(format!("{}: {} must be a list, got {}", F, W, json_kind(other)))),
    };
    if items.len() >= MAX_IC_POINTS {
        return Err(err(format!(
            "{}: {} has {} entries, more than the {} this release accepts",
            F,
            W,
            items.len(),
            MAX_IC_POINTS - 1
        )));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, x)| fr(x, &format!("public_inputs[{}]", i)))
        .collect()
}

// =========================================================
// Builtin
// =========================================================

fn b_groth16_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.len() != 3 {
        return Err(err(format!("{}(vk, proof, public_inputs) takes exactly 3 arguments", F)));
    }
    let (vk, n_public) = parse_vk(&json_arg(args.first(), "vk")?)?;
    let proof = parse_proof(&json_arg(args.get(1), "proof")?)?;
    let inputs = parse_public_inputs(args.get(2))?;
    if inputs.len() != n_public {
        return Err(err(format!(
            "{}: the vk expects {} public input(s) (nPublic) but {} were given",
            F,
            n_public,
            inputs.len()
        )));
    }
    let pvk = prepare_verifying_key(&vk);
    // Con los largos ya cotejados, `verify_proof` no tiene por qué fallar; si lo hiciera es un
    // defecto de la vk (nunca "la prueba es mala") → error, no `false`.
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs)
        .map_err(|e| err(format!("{}: the verifying key is malformed: {:?}", F, e)))?;
    Ok(syn_bool(ok))
}

/// Registra `groth16_verify`. Puro: sin capability. Lo llama el runtime nativo y el perfil wasm.
pub fn register_zk_builtins(interp: &Interpreter) {
    interp.register_builtin("groth16_verify", 3, Rc::new(|_i, args, _l| b_groth16_verify(args)));
}

// =========================================================
// Tests: vectores reales de snarkjs 0.7.6 (fixtures/zk/SOURCE.md) + los rechazos del contrato.
// =========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use synsema_core::types::{syn_list, syn_text};

    // Multiplier (a*b = c) de arkworks-rs/circom-compat: nPublic = 1 (la salida c).
    const MULT_VK: &str = include_str!("fixtures/zk/multiplier_vk.json");
    const MULT_PROOF_1: &str = include_str!("fixtures/zk/multiplier_proof_1.json");
    const MULT_PUBLIC_1: &str = include_str!("fixtures/zk/multiplier_public_1.json");
    const MULT_PROOF_2: &str = include_str!("fixtures/zk/multiplier_proof_2.json");
    const MULT_PUBLIC_2: &str = include_str!("fixtures/zk/multiplier_public_2.json");
    // Multiplier(1000) de iden3/snarkjs test/groth16: nPublic = 2 (salida c + entrada pública a).
    const M1000_VK: &str = include_str!("fixtures/zk/multiplier1000_vk.json");
    const M1000_PROOF: &str = include_str!("fixtures/zk/multiplier1000_proof.json");
    const M1000_PUBLIC: &str = include_str!("fixtures/zk/multiplier1000_public.json");
    // vk real de PLONK (iden3/snarkjs test/circuit2): protocolo que NO soportamos.
    const PLONK_VK: &str = include_str!("fixtures/zk/plonk_vk.json");

    fn t(s: impl AsRef<str>) -> SynValue {
        syn_text(s.as_ref())
    }

    fn inputs(list: &[&str]) -> SynValue {
        syn_list(list.iter().map(|s| syn_text(*s)).collect())
    }

    fn verify(vk: SynValue, proof: SynValue, public: SynValue) -> Result<bool, String> {
        match b_groth16_verify(&[vk, proof, public]) {
            Ok(SynValue::Bool(b)) => Ok(b),
            Ok(other) => panic!("esperaba bool, got {}", other),
            Err(Control::Error(e)) => Err(e.to_string()),
            Err(_) => panic!("control inesperado"),
        }
    }

    fn expect_err(r: Result<bool, String>, needle: &str) {
        match r {
            Err(msg) => assert!(
                msg.contains(needle),
                "el error debía mencionar {:?}, fue: {}",
                needle,
                msg
            ),
            Ok(b) => panic!("esperaba error con {:?}, devolvió {}", needle, b),
        }
    }

    /// Edita un JSON con un closure y lo devuelve como texto.
    fn edit(json: &str, f: impl FnOnce(&mut J)) -> String {
        let mut v: J = serde_json::from_str(json).unwrap();
        f(&mut v);
        v.to_string()
    }

    /// L17: `vk.IC` y `public_inputs` tienen tope (2^16 puntos / 2^16 - 1 entradas) y el error
    /// llega ANTES de validar un solo punto (antes: IC de 20 001 puntos = 0,8 s por llamada).
    #[test]
    fn ic_and_public_inputs_are_capped_before_parsing_points() {
        let point = serde_json::from_str::<J>(MULT_VK).unwrap()["IC"][0].clone();
        let huge = edit(MULT_VK, |v| {
            v["nPublic"] = J::from(65_536u64);
            v["IC"] = J::Array(std::iter::repeat(point.clone()).take(65_537).collect());
        });
        let t0 = std::time::Instant::now();
        expect_err(verify(t(&huge), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "vk.IC has 65537 points, more than the 65536 this release accepts");
        assert!(t0.elapsed().as_secs() < 10, "el tope tiene que cortar antes de validar puntos: {:?}", t0.elapsed());
        // nPublic fuera de rango con un IC chico: también error inmediato.
        let big_n = edit(MULT_VK, |v| v["nPublic"] = J::from(65_536u64));
        expect_err(verify(t(&big_n), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "vk.nPublic is 65536, more than the 65535");
        // public_inputs con 65 536 entradas: tope antes de parsear cada una.
        let many: Vec<&str> = vec!["1"; 65_536];
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&many)), "public_inputs has 65536 entries, more than the 65535");
        // Justo debajo del tope no es el tope lo que falla (sino el largo vs nPublic).
        let ok_len: Vec<&str> = vec!["1"; 65_535];
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&ok_len)), "expects 1 public input(s) (nPublic) but 65535 were given");
    }

    fn fq_str(x: &Fq) -> String {
        BigUint::from(x.into_bigint()).to_string()
    }

    fn q_modulus() -> BigUint {
        BigUint::from(Fq::MODULUS)
    }

    // ---------- vectores reales: true ----------

    #[test]
    fn multiplier_proof_1_verifies_from_json_texts() {
        assert_eq!(verify(t(MULT_VK), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), Ok(true));
    }

    #[test]
    fn multiplier_proof_1_verifies_with_input_list() {
        assert_eq!(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&["33"])), Ok(true));
    }

    /// Segunda prueba del mismo circuito con a = r − 2: la salida pública es un escalar a un pelo
    /// del módulo (chequea el camino "grande pero canónico").
    #[test]
    fn multiplier_proof_2_verifies_near_modulus_scalar() {
        assert_eq!(verify(t(MULT_VK), t(MULT_PROOF_2), t(MULT_PUBLIC_2)), Ok(true));
    }

    /// El mismo vector con vk y proof como MAPS de Synsema (json_decode) y la entrada como número.
    #[test]
    fn multiplier_verifies_from_maps_and_integer_input() {
        let vk = crate::json::json_to_syn(&serde_json::from_str(MULT_VK).unwrap());
        let proof = crate::json::json_to_syn(&serde_json::from_str(MULT_PROOF_1).unwrap());
        let public = syn_list(vec![SynValue::Number(Number::Int(33))]);
        assert!(matches!(vk, SynValue::Map(_)));
        assert_eq!(verify(vk, proof, public), Ok(true));
    }

    #[test]
    fn multiplier1000_two_public_inputs_verify() {
        assert_eq!(verify(t(M1000_VK), t(M1000_PROOF), t(M1000_PUBLIC)), Ok(true));
    }

    // ---------- prueba inválida bien formada: false ----------

    #[test]
    fn wrong_public_input_is_false() {
        assert_eq!(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&["34"])), Ok(false));
        // Público de la prueba 2 con la prueba 1 (lo mismo que dice `snarkjs groth16 verify`).
        assert_eq!(verify(t(MULT_VK), t(MULT_PROOF_1), t(MULT_PUBLIC_2)), Ok(false));
    }

    #[test]
    fn multiplier1000_swapped_public_inputs_false() {
        assert_eq!(
            verify(t(M1000_VK), t(M1000_PROOF), inputs(&["11", "19820469076730107577691234630797803937210158605698999776717232705083708883456"])),
            Ok(false)
        );
    }

    /// pi_a → −pi_a (y ↦ q − y): sigue siendo un punto válido de G1, la prueba deja de cerrar.
    #[test]
    fn negated_pi_a_is_false() {
        let proof = edit(MULT_PROOF_1, |p| {
            let y = p["pi_a"][1].as_str().unwrap().parse::<BigUint>().unwrap();
            p["pi_a"][1] = J::String((q_modulus() - y).to_string());
        });
        assert_eq!(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), Ok(false));
    }

    /// pi_a y pi_c intercambiados: dos puntos válidos en el lugar equivocado.
    #[test]
    fn swapped_pi_a_pi_c_is_false() {
        let proof = edit(MULT_PROOF_1, |p| {
            let a = p["pi_a"].clone();
            p["pi_a"] = p["pi_c"].clone();
            p["pi_c"] = a;
        });
        assert_eq!(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), Ok(false));
    }

    /// Prueba de otro circuito contra esta vk (misma cantidad de públicos): false, no error.
    #[test]
    fn proof_from_another_circuit_is_false() {
        let proof = edit(M1000_PROOF, |_| {});
        assert_eq!(verify(t(MULT_VK), t(proof), inputs(&["33"])), Ok(false));
    }

    /// El infinito de snarkjs `["0","1","0"]` se acepta como punto (la prueba no cierra → false).
    #[test]
    fn infinity_encoding_is_accepted_as_a_point() {
        let proof = edit(MULT_PROOF_1, |p| {
            p["pi_c"] = serde_json::json!(["0", "1", "0"]);
        });
        assert_eq!(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), Ok(false));
        let proof = edit(MULT_PROOF_1, |p| {
            p["pi_b"] = serde_json::json!([["0", "0"], ["1", "0"], ["0", "0"]]);
        });
        assert_eq!(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), Ok(false));
    }

    // ---------- formato dudoso: error ----------

    /// Un dígito cambiado en pi_a deja el punto fuera de la curva: error, no false.
    #[test]
    fn mutated_pi_a_digit_is_an_error_off_curve() {
        let proof = edit(MULT_PROOF_1, |p| {
            let x = p["pi_a"][0].as_str().unwrap().to_string();
            let last = x.as_bytes()[x.len() - 1];
            let flipped = if last == b'7' { b'8' } else { b'7' };
            let mut bytes = x.into_bytes();
            let n = bytes.len();
            bytes[n - 1] = flipped;
            p["pi_a"][0] = J::String(String::from_utf8(bytes).unwrap());
        });
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "not on the BN254 G1 curve");
    }

    #[test]
    fn mutated_pi_b_is_an_error_off_curve() {
        let proof = edit(MULT_PROOF_1, |p| {
            p["pi_b"][0][1] = J::String("12345".to_string());
        });
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "not on the BN254 G2 curve");
    }

    /// Punto de la curva G2 pero FUERA del subgrupo de orden r (cofactor enorme: casi cualquier
    /// x da uno). Es el chequeo que protege la solidez del pairing.
    #[test]
    fn g2_point_outside_subgroup_is_an_error() {
        let mut found = None;
        for i in 1u64..200 {
            let x = Fq2::new(Fq::from(i), Fq::from(7u64));
            if let Some(p) = G2Affine::get_point_from_x_unchecked(x, true) {
                assert!(p.is_on_curve());
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    found = Some(p);
                    break;
                }
            }
        }
        let p = found.expect("algún x en 1..200 tiene un punto fuera del subgrupo");
        let point = serde_json::json!([
            [fq_str(&p.x.c0), fq_str(&p.x.c1)],
            [fq_str(&p.y.c0), fq_str(&p.y.c1)],
            ["1", "0"]
        ]);
        let proof = edit(MULT_PROOF_1, |pr| pr["pi_b"] = point.clone());
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "not in the G2 prime-order subgroup");
        let vk = edit(MULT_VK, |v| v["vk_gamma_2"] = point.clone());
        expect_err(verify(t(vk), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "not in the G2 prime-order subgroup");
    }

    #[test]
    fn projective_z_not_one_is_an_error() {
        let proof = edit(MULT_PROOF_1, |p| p["pi_a"][2] = J::String("2".to_string()));
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "must be normalized (z = 1");
        let proof = edit(MULT_PROOF_1, |p| p["pi_b"][2] = serde_json::json!(["1", "1"]));
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "must be normalized (z = [1, 0]");
        // z = 0 sin ser el infinito canónico.
        let proof = edit(MULT_PROOF_1, |p| p["pi_c"][2] = J::String("0".to_string()));
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "not the point at infinity");
    }

    #[test]
    fn non_canonical_coordinate_is_an_error() {
        // x + q: mismo residuo, otra codificación → se rechaza.
        let proof = edit(MULT_PROOF_1, |p| {
            let x = p["pi_a"][0].as_str().unwrap().parse::<BigUint>().unwrap();
            p["pi_a"][0] = J::String((x + q_modulus()).to_string());
        });
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "not canonical");
    }

    #[test]
    fn scalar_at_or_above_r_is_an_error() {
        let r = BigUint::from(Fr::MODULUS).to_string();
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&[&r])), "not canonical");
        // r − 1 es canónico: se acepta (y la prueba no cierra).
        let r_minus_1 = (BigUint::from(Fr::MODULUS) - BigUint::from(1u8)).to_string();
        assert_eq!(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&[&r_minus_1])), Ok(false));
    }

    #[test]
    fn bad_public_input_encodings_are_errors() {
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&["-1"])), "only digits");
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&["0x21"])), "only digits");
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&[" 33"])), "only digits");
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&[""])), "is empty");
        let float = syn_list(vec![SynValue::Number(Number::Float(33.0))]);
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), float), "whole numbers");
        let negative = syn_list(vec![SynValue::Number(Number::Int(-33))]);
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), negative), "non-negative");
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), t("33")), "must be a list");
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), t("not json")), "invalid JSON");
        let long = "9".repeat(MAX_DECIMAL_DIGITS + 1);
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&[&long])), "digits (max");
    }

    #[test]
    fn wrong_curve_is_an_error() {
        let vk = edit(MULT_VK, |v| v["curve"] = J::String("bls12381".to_string()));
        expect_err(verify(t(vk), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "curve \"bls12381\"");
        let proof = edit(MULT_PROOF_1, |p| p["curve"] = J::String("bls12381".to_string()));
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "curve \"bls12381\"");
        // El sinónimo bn254 se acepta.
        let vk = edit(MULT_VK, |v| v["curve"] = J::String("bn254".to_string()));
        assert_eq!(verify(t(vk), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), Ok(true));
    }

    #[test]
    fn wrong_protocol_is_an_error() {
        // vk REAL de PLONK exportada por snarkjs: se rechaza por el protocolo, antes de mirar la forma.
        expect_err(verify(t(PLONK_VK), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "protocol \"plonk\"");
        let proof = edit(MULT_PROOF_1, |p| p["protocol"] = J::String("plonk".to_string()));
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "protocol \"plonk\"");
        let vk = edit(MULT_VK, |v| {
            v.as_object_mut().unwrap().remove("protocol");
        });
        expect_err(verify(t(vk), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "missing \"protocol\"");
        // En la prueba `protocol`/`curve` son opcionales (hay tooling que los recorta).
        let proof = edit(MULT_PROOF_1, |p| {
            let o = p.as_object_mut().unwrap();
            o.remove("protocol");
            o.remove("curve");
        });
        assert_eq!(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), Ok(true));
    }

    #[test]
    fn inconsistent_npublic_is_an_error() {
        // nPublic ≠ IC.len() − 1.
        let vk = edit(MULT_VK, |v| v["nPublic"] = serde_json::json!(2));
        expect_err(verify(t(vk), t(MULT_PROOF_1), inputs(&["33", "1"])), "vk.IC has 2 points");
        // nPublic consistente con IC pero no con las entradas dadas.
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&["33", "1"])), "expects 1 public input(s)");
        expect_err(verify(t(MULT_VK), t(MULT_PROOF_1), inputs(&[])), "expects 1 public input(s)");
        expect_err(verify(t(M1000_VK), t(M1000_PROOF), inputs(&["11"])), "expects 2 public input(s)");
    }

    #[test]
    fn missing_or_malformed_fields_are_errors() {
        let vk = edit(MULT_VK, |v| {
            v.as_object_mut().unwrap().remove("IC");
        });
        expect_err(verify(t(vk), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "missing \"IC\"");
        let proof = edit(MULT_PROOF_1, |p| {
            p.as_object_mut().unwrap().remove("pi_b");
        });
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "missing \"pi_b\"");
        let proof = edit(MULT_PROOF_1, |p| p["pi_a"] = serde_json::json!(["1", "2"]));
        expect_err(verify(t(MULT_VK), t(proof), t(MULT_PUBLIC_1)), "with 3 entries, got 2");
        expect_err(verify(t("[1, 2]"), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "vk must be a map");
        expect_err(verify(t("{not json"), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), "vk is not valid JSON");
        expect_err(
            verify(SynValue::Number(Number::Int(1)), t(MULT_PROOF_1), t(MULT_PUBLIC_1)),
            "vk must be a map or a JSON text",
        );
        // vk_alphabeta_12 se ignora: quitarlo no cambia nada.
        let vk = edit(MULT_VK, |v| {
            v.as_object_mut().unwrap().remove("vk_alphabeta_12");
        });
        assert_eq!(verify(t(vk), t(MULT_PROOF_1), t(MULT_PUBLIC_1)), Ok(true));
    }

    #[test]
    fn arity_is_enforced() {
        match b_groth16_verify(&[t(MULT_VK), t(MULT_PROOF_1)]) {
            Err(Control::Error(e)) => assert!(e.to_string().contains("exactly 3 arguments")),
            _ => panic!("esperaba error de aridad"),
        }
    }

    /// Chequeo de la convención c0/c1 de snarkjs contra arkworks sin pasar por el pairing: el
    /// generador de G2 de BN254 (el que usa snarkjs para `vk_gamma_2` en toda ceremonia estándar)
    /// debe coincidir coordenada a coordenada con el de la vk.
    #[test]
    fn snarkjs_g2_coordinate_order_matches_arkworks_generator() {
        let vk: J = serde_json::from_str(MULT_VK).unwrap();
        let gamma = g2(&vk["vk_gamma_2"], "vk.vk_gamma_2").map_err(|_| "parse").unwrap();
        assert_eq!(gamma, G2Affine::generator());
        let alpha = g1(&vk["vk_alpha_1"], "vk.vk_alpha_1").map_err(|_| "parse").unwrap();
        assert!(!alpha.is_zero());
    }
}

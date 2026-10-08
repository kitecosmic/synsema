//! `attestation_verify` con `format: "sev-snp"`: el reporte de AMD SEV-SNP (el `outblob` de
//! configfs-tsm, 1184 bytes) firmado por la VCEK o la VLEK, con la cadena VEK ← ASK/ASVK ← ARK de
//! AMD por producto (Milan, Genoa, Turin). Puro: sin red, sin reloj, compila a wasm.
//!
//! Orden de los chequeos (cada uno falla cerrado y nombra el campo):
//! 1. tamaño `0x4A0` y `VERSION` ∈ {2, 3, 4, 5};
//! 2. `SIGNATURE_ALGO` = 1 (ECDSA P-384 con SHA-384);
//! 3. `KEY_INFO.SIGNING_KEY` = 0 (VCEK) o 1 (VLEK); 7 = sin firmar;
//! 4. la VEK sale de `opts.vek` o de la tabla de certificados de `opts.aux` (si vienen las dos y
//!    difieren, error); las entradas ASK/ARK de la tabla se IGNORAN: la cadena usa las embebidas;
//! 5. producto por la extensión `productName` de la VEK, cruzado con `CPUID_FAM_ID`/`CPUID_MOD_ID`
//!    si `VERSION >= 3`;
//! 6. cadena con las raíces EMBEBIDAS, pineadas por SHA-256: vigencia de cada certificado contra
//!    `now` y firmas RSASSA-PSS (SHA-384, MGF1-SHA-384, sal de 48 bytes, nada más);
//! 7. firma ECDSA P-384 del reporte con la VEK sobre `doc[0..0x2A0]`;
//! 8. TCB de la VEK (blSPL/teeSPL/snpSPL/ucodeSPL y fmcSPL en Turin) = `REPORTED_TCB`; en una VCEK
//!    además `hwID` = `CHIP_ID`;
//! 9. `POLICY.DEBUG` prendido es error, sin opción.
//!
//! Fuentes de la disposición: AMD SEV-SNP ABI (pub. 56860), `virtee/sev` (mapeo CPUID → producto y
//! TCB de Turin) y `virtee/snpguest` (extensiones de la VEK). Milan está ejercitado con un reporte
//! real de AWS (`fixtures/attestation/aws_snp_c6a_*`); Genoa y Turin no tienen fixture.
//!
//! ## Raíces embebidas (procedencia)
//!
//! `fixtures/attestation/amd/{ark,ask,asvk}-<producto>.der` son los certificados de
//! `https://kdsintf.amd.com/{vcek,vlek}/v1/<Producto>/cert_chain` (bajados el 2026-10-07; los PEM
//! originales están al lado), en DER. Sus SHA-256 son las constantes [`AMD_PINS`]: el verificador
//! los recomputa antes de usarlos y un test los fija.

use p384::ecdsa::signature::Verifier as _;
use sha2::{Digest, Sha256, Sha384};
use x509_parser::oid_registry::{OID_NIST_HASH_SHA384, OID_PKCS1_RSAENCRYPTION, OID_PKCS1_RSASSAPSS};
use x509_parser::prelude::*;
use x509_parser::signature_algorithm::SignatureAlgorithm;

use synsema_core::bytesutil::hex_encode;

use crate::attestation::{check_ca, check_validity, entry_of, p384_key_of, parse_cert, ChainEntry};
use crate::webauth::DerReader;

/// Tamaño del reporte (`ATTESTATION_REPORT`, tabla 23 del ABI).
pub const REPORT_LEN: usize = 0x4A0;
/// Lo firmado: todo lo anterior a `SIGNATURE`.
const SIGNED_LEN: usize = 0x2A0;

pub const AMD_ARK_MILAN_DER: &[u8] = include_bytes!("fixtures/attestation/amd/ark-milan.der");
pub const AMD_ASK_MILAN_DER: &[u8] = include_bytes!("fixtures/attestation/amd/ask-milan.der");
pub const AMD_ASVK_MILAN_DER: &[u8] = include_bytes!("fixtures/attestation/amd/asvk-milan.der");
pub const AMD_ARK_GENOA_DER: &[u8] = include_bytes!("fixtures/attestation/amd/ark-genoa.der");
pub const AMD_ASK_GENOA_DER: &[u8] = include_bytes!("fixtures/attestation/amd/ask-genoa.der");
pub const AMD_ASVK_GENOA_DER: &[u8] = include_bytes!("fixtures/attestation/amd/asvk-genoa.der");
pub const AMD_ARK_TURIN_DER: &[u8] = include_bytes!("fixtures/attestation/amd/ark-turin.der");
pub const AMD_ASK_TURIN_DER: &[u8] = include_bytes!("fixtures/attestation/amd/ask-turin.der");
pub const AMD_ASVK_TURIN_DER: &[u8] = include_bytes!("fixtures/attestation/amd/asvk-turin.der");

/// `(producto, sha256(ARK), sha256(ASK), sha256(ASVK))` de los DER embebidos.
pub const AMD_PINS: &[(Product, &str, &str, &str)] = &[
    (
        Product::Milan,
        "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
        "67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b",
        "c5e081f59b7efab1fe2f8b505e159704e72f29cab7ef7cf628a05a42439082f5",
    ),
    (
        Product::Genoa,
        "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
        "5464738c1546aed5f2cecf1dc98c5c960a92e8913238a61711bc90ec6e828521",
        "197e610743a917d6b9bb982a5a9226ccc0a15b611be0619e626aca9151457372",
    ),
    (
        Product::Turin,
        "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
        "5b77ef5fe7a7a004fd9032668fba9d0fda22f88c4442069a479636a6ae3b3185",
        "104e10a8bd060a3c20a434261a57d0588fd65a88915b4f65b08bdecaf8df1a3c",
    ),
];

// GUIDs de la tabla de certificados (GHCB spec, `SNP_GUEST_REQUEST` extendido), en el orden de
// bytes del texto, que es como los escribe el host.
const GUID_VLEK: [u8; 16] = [0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1];
const GUID_VCEK: [u8; 16] = [0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd];
const GUID_ASK: [u8; 16] = [0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82];
const GUID_ARK: [u8; 16] = [0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae];

// Extensiones de la VEK (AMD "VCEK Certificate and KDS Interface Specification").
const OID_PRODUCT_NAME: &str = "1.3.6.1.4.1.3704.1.2";
const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";
const OID_FMC_SPL: &str = "1.3.6.1.4.1.3704.1.3.9";
const OID_HW_ID: &str = "1.3.6.1.4.1.3704.1.4";
const OID_CSP_ID: &str = "1.3.6.1.4.1.3704.1.5";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";

/// Bit 19 de `GUEST_POLICY`: el hipervisor puede depurar (leer y escribir) la memoria del guest.
const POLICY_DEBUG: u64 = 1 << 19;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    Milan,
    Genoa,
    Turin,
}

impl Product {
    pub fn name(self) -> &'static str {
        match self {
            Product::Milan => "Milan",
            Product::Genoa => "Genoa",
            Product::Turin => "Turin",
        }
    }

    /// `CPUID_FAM_ID`/`CPUID_MOD_ID` → producto, como `Generation::identify_cpu` de `virtee/sev`.
    fn from_cpuid(family: u8, model: u8) -> Option<Product> {
        match (family, model) {
            (0x19, 0x00..=0x0f) => Some(Product::Milan),
            (0x19, 0x10..=0x1f) | (0x19, 0xa0..=0xaf) => Some(Product::Genoa),
            (0x1a, 0x00..=0x11) => Some(Product::Turin),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKey {
    Vcek,
    Vlek,
}

impl SigningKey {
    pub fn name(self) -> &'static str {
        match self {
            SigningKey::Vcek => "vcek",
            SigningKey::Vlek => "vlek",
        }
    }
    fn label(self) -> &'static str {
        match self {
            SigningKey::Vcek => "the VCEK",
            SigningKey::Vlek => "the VLEK",
        }
    }
}

/// Las tres raíces de un producto (DER).
pub(crate) struct ProductRoots<'a> {
    pub ark: &'a [u8],
    pub ask: &'a [u8],
    pub asvk: &'a [u8],
}

/// Las raíces embebidas de `product`, recién después de comprobar sus SHA-256 contra [`AMD_PINS`].
pub(crate) fn pinned_roots(product: Product) -> Result<ProductRoots<'static>, String> {
    let roots = match product {
        Product::Milan => ProductRoots { ark: AMD_ARK_MILAN_DER, ask: AMD_ASK_MILAN_DER, asvk: AMD_ASVK_MILAN_DER },
        Product::Genoa => ProductRoots { ark: AMD_ARK_GENOA_DER, ask: AMD_ASK_GENOA_DER, asvk: AMD_ASVK_GENOA_DER },
        Product::Turin => ProductRoots { ark: AMD_ARK_TURIN_DER, ask: AMD_ASK_TURIN_DER, asvk: AMD_ASVK_TURIN_DER },
    };
    let (_, ark, ask, asvk) = AMD_PINS.iter().find(|p| p.0 == product).ok_or("internal: no AMD pin for the product")?;
    for (der, pin, what) in [(roots.ark, ark, "ARK"), (roots.ask, ask, "ASK"), (roots.asvk, asvk, "ASVK")] {
        if hex_encode(&Sha256::digest(der)) != *pin {
            return Err(format!("internal: the embedded AMD {} for {} does not match its pinned SHA-256", what, product.name()));
        }
    }
    Ok(roots)
}

/// Una TCB decodificada según el producto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tcb {
    pub fmc: Option<u8>,
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// `TCB_VERSION` (u64 LE) → campos: Milan/Genoa `bl, tee, 0, 0, 0, 0, snp, ucode`; Turin
/// `fmc, bl, tee, snp, 0, 0, 0, ucode`. Un byte reservado distinto de cero es error.
fn decode_tcb(raw: &[u8], product: Product, field: &str) -> Result<Tcb, String> {
    let (tcb, reserved) = match product {
        Product::Milan | Product::Genoa => (Tcb { fmc: None, boot_loader: raw[0], tee: raw[1], snp: raw[6], microcode: raw[7] }, &raw[2..6]),
        Product::Turin => (Tcb { fmc: Some(raw[0]), boot_loader: raw[1], tee: raw[2], snp: raw[3], microcode: raw[7] }, &raw[4..7]),
    };
    if reserved.iter().any(|b| *b != 0) {
        return Err(format!("report {} has non-zero reserved bytes for {} ({})", field, product.name(), hex_encode(raw)));
    }
    Ok(tcb)
}

/// Lo que devuelve una verificación exitosa (la forma normalizada la arma `attestation.rs`).
pub(crate) struct SnpVerified {
    pub version: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub report_data: Vec<u8>,
    pub measurement: Vec<u8>,
    pub host_data: Vec<u8>,
    pub chip_id: Vec<u8>,
    pub product: Product,
    pub signing_key: SigningKey,
    pub csp_id: Option<String>,
    pub reported: Tcb,
    pub current: Tcb,
    pub committed: Tcb,
    pub launch: Tcb,
    /// Hoja (VEK) primero, como el resto de los formatos.
    pub chain: Vec<ChainEntry>,
}

fn u32_at(doc: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(doc[off..off + 4].try_into().expect("4 bytes"))
}

fn u64_at(doc: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(doc[off..off + 8].try_into().expect("8 bytes"))
}

fn guid_text(g: &[u8]) -> String {
    let h = hex_encode(g);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// La entrada `want` de la tabla de certificados de `aux` (`GUID ‖ offset u32 LE ‖ length u32 LE`,
/// hasta una entrada toda en cero; offsets relativos al inicio de `aux`). Un GUID desconocido,
/// una entrada repetida o un rango fuera del blob son error.
fn aux_entry<'a>(aux: &'a [u8], want: &[u8; 16]) -> Result<Option<&'a [u8]>, String> {
    let mut found: Option<&'a [u8]> = None;
    let mut seen: Vec<[u8; 16]> = Vec::new();
    let mut i = 0usize;
    loop {
        let entry = aux.get(i..i + 24).ok_or("opts.aux: the certificate table has no terminating all-zero entry")?;
        if entry.iter().all(|b| *b == 0) {
            break;
        }
        let guid: [u8; 16] = entry[..16].try_into().expect("16 bytes");
        let name = if guid == GUID_VLEK {
            "VLEK"
        } else if guid == GUID_VCEK {
            "VCEK"
        } else if guid == GUID_ASK {
            "ASK"
        } else if guid == GUID_ARK {
            "ARK"
        } else {
            return Err(format!("opts.aux: unknown certificate GUID {} in the table", guid_text(&guid)));
        };
        if seen.contains(&guid) {
            return Err(format!("opts.aux: the {} entry appears twice in the table", name));
        }
        seen.push(guid);
        let off = u32::from_le_bytes(entry[16..20].try_into().expect("4")) as usize;
        let len = u32::from_le_bytes(entry[20..24].try_into().expect("4")) as usize;
        if len == 0 {
            return Err(format!("opts.aux: the {} entry is empty (length 0)", name));
        }
        let body = off
            .checked_add(len)
            .and_then(|end| aux.get(off..end))
            .ok_or_else(|| format!("opts.aux: the {} entry points outside the blob (offset {}, length {}, blob {} bytes)", name, off, len, aux.len()))?;
        if &guid == want {
            found = Some(body);
        }
        i += 24;
    }
    Ok(found)
}

/// La VLEK (o, si no hay, la VCEK) de una tabla `aux`, para saber cuándo vence un documento
/// SEV-SNP (T10). `None` si la tabla no la trae o está rota (la verificación lo dirá).
pub(crate) fn vek_in_aux(aux: &[u8]) -> Option<Vec<u8>> {
    let vlek = aux_entry(aux, &GUID_VLEK).ok().flatten();
    let vcek = aux_entry(aux, &GUID_VCEK).ok().flatten();
    vlek.or(vcek).map(<[u8]>::to_vec)
}

/// Valor de una extensión por OID (texto con puntos); `None` si no está.
fn ext_value<'a>(cert: &'a X509Certificate<'_>, oid: &str) -> Option<&'a [u8]> {
    cert.extensions().iter().find(|e| e.oid.to_id_string() == oid).map(|e| e.value)
}

/// Una extensión SPL: `INTEGER` DER no negativo que cabe en un byte.
fn ext_spl(cert: &X509Certificate<'_>, oid: &str, field: &str, what: &str) -> Result<u8, String> {
    let raw = ext_value(cert, oid).ok_or_else(|| format!("{} has no {} extension ({})", what, field, oid))?;
    let mut r = DerReader::new(raw);
    let (tag, body) = r.tlv().map_err(|e| format!("{} {} extension: {}", what, field, e))?;
    if tag != 0x02 || !r.done() || body.is_empty() || body.len() > 2 || body[0] & 0x80 != 0 {
        return Err(format!("{} {} extension is not a small non-negative INTEGER", what, field));
    }
    let v = body.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32);
    u8::try_from(v).map_err(|_| format!("{} {} extension is {}, above 255", what, field, v))
}

/// Una extensión `IA5String`.
fn ext_ia5(cert: &X509Certificate<'_>, oid: &str, field: &str, what: &str) -> Result<Option<String>, String> {
    let Some(raw) = ext_value(cert, oid) else { return Ok(None) };
    let mut r = DerReader::new(raw);
    let (tag, body) = r.tlv().map_err(|e| format!("{} {} extension: {}", what, field, e))?;
    if tag != 0x16 || !r.done() || !body.is_ascii() {
        return Err(format!("{} {} extension is not an IA5String", what, field));
    }
    Ok(Some(String::from_utf8_lossy(body).into_owned()))
}

/// RSASSA-PSS con SHA-384, MGF1-SHA-384, sal de 48 y trailer 1: lo único que firma AMD. Cualquier
/// otro algoritmo o parámetro es error.
fn check_pss_params(alg: &AlgorithmIdentifier<'_>, what: &str) -> Result<(), String> {
    if alg.algorithm != OID_PKCS1_RSASSAPSS {
        return Err(format!("{} is not signed with RSASSA-PSS (algorithm {})", what, alg.algorithm.to_id_string()));
    }
    let params = match SignatureAlgorithm::try_from(alg) {
        Ok(SignatureAlgorithm::RSASSA_PSS(p)) => p,
        _ => return Err(format!("{} has malformed RSASSA-PSS parameters", what)),
    };
    if *params.hash_algorithm_oid() != OID_NIST_HASH_SHA384 {
        return Err(format!("{} RSASSA-PSS hash is {}, not SHA-384", what, params.hash_algorithm_oid().to_id_string()));
    }
    let mgf = params.mask_gen_algorithm().map_err(|_| format!("{} has a malformed RSASSA-PSS mask generation function", what))?;
    if mgf.mgf.to_id_string() != OID_MGF1 || mgf.hash != OID_NIST_HASH_SHA384 {
        return Err(format!("{} RSASSA-PSS mask generation is not MGF1 with SHA-384", what));
    }
    if params.salt_length() != 48 {
        return Err(format!("{} RSASSA-PSS salt length is {}, not 48", what, params.salt_length()));
    }
    if params.trailer_field() != 1 {
        return Err(format!("{} RSASSA-PSS trailer field is {}, not 1", what, params.trailer_field()));
    }
    Ok(())
}

/// La clave RSA del SPKI de un emisor (`rsaEncryption` o `RSASSA-PSS`; PKCS#1 adentro).
fn rsa_key_of(cert: &X509Certificate<'_>, what: &str) -> Result<rsa::RsaPublicKey, String> {
    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_PKCS1_RSAENCRYPTION && spki.algorithm.algorithm != OID_PKCS1_RSASSAPSS {
        return Err(format!("{} public key is not RSA", what));
    }
    let mut outer = DerReader::new(spki.subject_public_key.data.as_ref());
    let (tag, seq) = outer.tlv().map_err(|e| format!("{} RSA public key: {}", what, e))?;
    if tag != 0x30 || !outer.done() {
        return Err(format!("{} RSA public key is not a SEQUENCE", what));
    }
    let mut r = DerReader::new(seq);
    let (t1, n) = r.tlv().map_err(|e| format!("{} RSA public key: {}", what, e))?;
    let (t2, e) = r.tlv().map_err(|e| format!("{} RSA public key: {}", what, e))?;
    if t1 != 0x02 || t2 != 0x02 || !r.done() {
        return Err(format!("{} RSA public key is not SEQUENCE {{ n, e }}", what));
    }
    rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(n), rsa::BigUint::from_bytes_be(e)).map_err(|err| format!("{} RSA public key is not usable: {}", what, err))
}

/// `child` firmado por `issuer` con RSASSA-PSS/SHA-384/sal 48; emisor = sujeto byte a byte; el
/// algoritmo dentro del TBS es el mismo que el de afuera (RFC 5280 §4.1.1.2).
fn verify_pss_issued_by(child: &X509Certificate<'_>, issuer: &X509Certificate<'_>, what: &str) -> Result<(), String> {
    if child.signature_algorithm != child.tbs_certificate.signature {
        return Err(format!("{} signature algorithm differs between the TBS and the certificate", what));
    }
    check_pss_params(&child.signature_algorithm, what)?;
    if child.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(format!("{} issuer does not match the subject of its issuing certificate", what));
    }
    let key = rsa_key_of(issuer, &format!("the issuer of {}", what))?;
    let vk = rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(key, 48);
    let sig = rsa::pss::Signature::try_from(child.signature_value.data.as_ref()).map_err(|_| format!("{} signature is malformed", what))?;
    use rsa::signature::Verifier as _;
    vk.verify(child.tbs_certificate.as_ref(), &sig).map_err(|_| format!("{} signature does not verify against its issuer", what))
}

/// Verifica un reporte SEV-SNP. `roots` da las raíces de un producto: la API pública usa
/// [`pinned_roots`]; los tests inyectan una cadena propia para llegar a los chequeos que van después
/// de la firma (política) con un reporte sintético.
pub(crate) fn verify(
    doc: &[u8],
    aux: Option<&[u8]>,
    vek: Option<&[u8]>,
    now: i64,
    roots: &dyn Fn(Product) -> Result<ProductRoots<'static>, String>,
) -> Result<SnpVerified, String> {
    // 1. Tamaño y versión.
    if doc.len() != REPORT_LEN {
        return Err(format!("doc has {} bytes; a SEV-SNP report is {} (0x4A0)", doc.len(), REPORT_LEN));
    }
    let version = u32_at(doc, 0x00);
    if !(2..=5).contains(&version) {
        return Err(format!("report VERSION {} is not supported (2, 3, 4 or 5)", version));
    }
    // 2. Algoritmo.
    let sig_algo = u32_at(doc, 0x34);
    if sig_algo != 1 {
        return Err(format!("report SIGNATURE_ALGO is {}, not 1 (ECDSA P-384 with SHA-384)", sig_algo));
    }
    // 3. Qué clave firmó.
    let key_info = u32_at(doc, 0x48);
    // Bits 31:5 de KEY_INFO y la palabra de 0x4C están reservados (cero en el ABI): un valor de un
    // ABI que no conocemos se rechaza en vez de interpretarse.
    if key_info >> 5 != 0 {
        return Err(format!("report KEY_INFO has reserved bits set (0x{:08x})", key_info));
    }
    if u32_at(doc, 0x4C) != 0 {
        return Err("report reserved field at 0x4C is not zero".to_string());
    }
    let signing_key = match (key_info >> 2) & 0x7 {
        0 => SigningKey::Vcek,
        1 => SigningKey::Vlek,
        7 => return Err("report KEY_INFO.SIGNING_KEY is 7: the report is not signed".to_string()),
        other => return Err(format!("report KEY_INFO.SIGNING_KEY is {}, not 0 (VCEK) or 1 (VLEK)", other)),
    };
    let what = signing_key.label();

    // 4. La VEK.
    let from_aux = match aux {
        Some(a) => aux_entry(a, if signing_key == SigningKey::Vlek { &GUID_VLEK } else { &GUID_VCEK })?,
        None => None,
    };
    let vek_der: &[u8] = match (from_aux, vek) {
        (Some(a), Some(v)) if a != v => return Err(format!("opts.vek differs from {} in opts.aux", what)),
        (Some(a), _) => a,
        (None, Some(v)) => v,
        (None, None) => {
            return Err(format!(
                "the report is signed by {} but {} (pass opts.aux with the host certificate table, or opts.vek)",
                what,
                if aux.is_some() { format!("opts.aux has no {} entry and opts.vek is missing", &what[4..]) } else { "neither opts.aux nor opts.vek was given".to_string() }
            ))
        }
    };
    let vek_cert = parse_cert(vek_der, what)?;

    // 5. Producto.
    let product_name = ext_ia5(&vek_cert, OID_PRODUCT_NAME, "productName", what)?.ok_or_else(|| format!("{} has no productName extension ({})", what, OID_PRODUCT_NAME))?;
    let product = match product_name.split('-').next().unwrap_or("") {
        "Milan" => Product::Milan,
        "Genoa" => Product::Genoa,
        "Turin" => Product::Turin,
        _ => return Err(format!("{} productName {:?} is not Milan, Genoa or Turin", what, product_name)),
    };
    let (family, model) = (doc[0x188], doc[0x189]);
    if version >= 3 {
        match Product::from_cpuid(family, model) {
            Some(p) if p == product => {}
            Some(p) => return Err(format!("report CPUID family 0x{:02x} model 0x{:02x} is {}, but {} says {}", family, model, p.name(), what, product.name())),
            None => return Err(format!("report CPUID family 0x{:02x} model 0x{:02x} is not a known SEV-SNP product", family, model)),
        }
    } else if product == Product::Turin {
        return Err(format!("report VERSION {} cannot come from Turin (it needs VERSION >= 3)", version));
    }

    // 6. Cadena.
    let r = roots(product)?;
    let ark = parse_cert(r.ark, "the AMD ARK")?;
    let (inter_der, inter_what) = match signing_key {
        SigningKey::Vcek => (r.ask, "the AMD ASK"),
        SigningKey::Vlek => (r.asvk, "the AMD ASVK"),
    };
    let inter = parse_cert(inter_der, inter_what)?;
    check_validity(&ark, now, "the AMD ARK")?;
    check_validity(&inter, now, inter_what)?;
    check_validity(&vek_cert, now, what)?;
    verify_pss_issued_by(&ark, &ark, "the AMD ARK")?;
    check_ca(&ark, 1, "the AMD ARK")?;
    verify_pss_issued_by(&inter, &ark, inter_what)?;
    check_ca(&inter, 0, inter_what)?;
    verify_pss_issued_by(&vek_cert, &inter, what)?;

    // 7. Firma del reporte.
    let vk = p384_key_of(&vek_cert, what)?;
    let mut raw_sig = Vec::with_capacity(96);
    for (off, comp) in [(0x2A0usize, "R"), (0x2E8usize, "S")] {
        let le = &doc[off..off + 72];
        if le[48..].iter().any(|b| *b != 0) {
            return Err(format!("report SIGNATURE.{} has non-zero bytes beyond the 48 of P-384", comp));
        }
        raw_sig.extend(le[..48].iter().rev());
    }
    let sig = p384::ecdsa::Signature::from_slice(&raw_sig).map_err(|_| "report SIGNATURE is not a valid P-384 signature".to_string())?;
    vk.verify(&doc[..SIGNED_LEN], &sig).map_err(|_| format!("report signature does not verify against {}", what))?;
    // El resto de la zona de firma (0x330..0x4A0) está reservado y fuera de lo firmado: tiene que ser
    // cero, así un mismo reporte no admite otras codificaciones.
    if doc[0x330..].iter().any(|b| *b != 0) {
        return Err("report SIGNATURE has non-zero reserved bytes after R and S".to_string());
    }

    // 8. TCB de la VEK contra REPORTED_TCB (no CURRENT_TCB).
    let reported = decode_tcb(&doc[0x180..0x188], product, "REPORTED_TCB")?;
    let current = decode_tcb(&doc[0x38..0x40], product, "CURRENT_TCB")?;
    let committed = decode_tcb(&doc[0x1E0..0x1E8], product, "COMMITTED_TCB")?;
    let launch = decode_tcb(&doc[0x1F0..0x1F8], product, "LAUNCH_TCB")?;
    let mut pairs = vec![
        (OID_BL_SPL, "blSPL", reported.boot_loader, "boot_loader"),
        (OID_TEE_SPL, "teeSPL", reported.tee, "tee"),
        (OID_SNP_SPL, "snpSPL", reported.snp, "snp"),
        (OID_UCODE_SPL, "ucodeSPL", reported.microcode, "microcode"),
    ];
    if let Some(fmc) = reported.fmc {
        pairs.push((OID_FMC_SPL, "fmcSPL", fmc, "fmc"));
    }
    for (oid, field, got, name) in pairs {
        let want = ext_spl(&vek_cert, oid, field, what)?;
        if want != got {
            return Err(format!("report REPORTED_TCB.{} is {} but {} {} is {}", name, got, what, field, want));
        }
    }
    let chip_id = doc[0x1A0..0x1E0].to_vec();
    let mut csp_id = None;
    match signing_key {
        SigningKey::Vcek => {
            if chip_id.iter().all(|b| *b == 0) {
                return Err("report CHIP_ID is masked (all zeros); a VCEK-signed report cannot be matched to its chip".to_string());
            }
            let raw = ext_value(&vek_cert, OID_HW_ID).ok_or_else(|| format!("{} has no hwID extension ({})", what, OID_HW_ID))?;
            let mut rd = DerReader::new(raw);
            let (tag, hwid) = rd.tlv().map_err(|e| format!("{} hwID extension: {}", what, e))?;
            if tag != 0x04 || !rd.done() || hwid.len() != 64 {
                return Err(format!("{} hwID extension is not a 64-byte OCTET STRING", what));
            }
            if hwid != chip_id.as_slice() {
                return Err(format!("report CHIP_ID does not match {} hwID", what));
            }
        }
        SigningKey::Vlek => csp_id = ext_ia5(&vek_cert, OID_CSP_ID, "csp_id", what)?,
    }

    // 9. Política: DEBUG prendido es error, siempre.
    let policy = u64_at(doc, 0x08);
    if policy & POLICY_DEBUG != 0 {
        return Err("report POLICY.DEBUG is set: the guest allows debug: the host can read its memory".to_string());
    }

    Ok(SnpVerified {
        version,
        policy,
        vmpl: u32_at(doc, 0x30),
        report_data: doc[0x50..0x90].to_vec(),
        measurement: doc[0x90..0xC0].to_vec(),
        host_data: doc[0xC0..0xE0].to_vec(),
        chip_id,
        product,
        signing_key,
        csp_id,
        reported,
        current,
        committed,
        launch,
        chain: vec![entry_of(&vek_cert), entry_of(&inter), entry_of(&ark)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[([u8; 16], u32, u32)], tail: usize) -> Vec<u8> {
        let mut t = Vec::new();
        for (g, off, len) in entries {
            t.extend_from_slice(g);
            t.extend_from_slice(&off.to_le_bytes());
            t.extend_from_slice(&len.to_le_bytes());
        }
        t.extend_from_slice(&[0; 24]);
        t.extend(std::iter::repeat(0xcc).take(tail));
        t
    }

    #[test]
    fn aux_table_entries() {
        let base = 24 * 3;
        let aux = table(&[(GUID_VLEK, base as u32, 4), (GUID_ASK, base as u32 + 4, 4)], 8);
        assert_eq!(aux_entry(&aux, &GUID_VLEK).unwrap(), Some(&[0xcc; 4][..]));
        assert_eq!(aux_entry(&aux, &GUID_VCEK).unwrap(), None);
        assert_eq!(vek_in_aux(&aux), Some(vec![0xcc; 4]));
        // Una entrada de largo 0 se nombra como tal (no como "falta").
        let aux = table(&[(GUID_VLEK, 48, 0)], 0);
        assert_eq!(aux_entry(&aux, &GUID_VLEK).unwrap_err(), "opts.aux: the VLEK entry is empty (length 0)");
        assert_eq!(vek_in_aux(&aux), None);
        // Repetida, fuera del blob, GUID desconocido, sin terminador.
        let aux = table(&[(GUID_ASK, 72, 1), (GUID_ASK, 72, 1)], 1);
        assert_eq!(aux_entry(&aux, &GUID_VLEK).unwrap_err(), "opts.aux: the ASK entry appears twice in the table");
        let aux = table(&[(GUID_VCEK, 40, 100)], 0);
        assert!(aux_entry(&aux, &GUID_VCEK).unwrap_err().contains("points outside the blob"));
        let aux = table(&[([7; 16], 48, 1)], 1);
        assert!(aux_entry(&aux, &GUID_VLEK).unwrap_err().contains("unknown certificate GUID"));
        let mut open_ended = GUID_ASK.to_vec();
        open_ended.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        assert!(aux_entry(&open_ended, &GUID_VLEK).unwrap_err().contains("no terminating all-zero entry"));
    }
}

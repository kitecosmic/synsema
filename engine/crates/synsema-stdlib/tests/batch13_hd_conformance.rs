//! Conformidad del Batch 13 (custodia HD + keystore V3 + PDA/SPL) contra
//! vectores de SDKs oficiales (G17). Es CÓDIGO DE CUSTODIA — cada primitiva se
//! ancla a un vector externo, jamás a "lo que produjo nuestro binario".
//!
//! Procedencia de los vectores (generados con el snippet de abajo, corrido en un
//! venv con los SDKs; los de BIP-39/SLIP-0010 son además los vectores OFICIALES
//! publicados en trezor/python-mnemonic y satoshilabs/slips):
//!   - BIP-39: `mnemonic` (la implementación de REFERENCIA de Trezor) — vectores
//!     canónicos entropy→frase→seed (passphrase "TREZOR").
//!   - HD ETH: `eth-account` (Ethereum Foundation; equivale a ethers
//!     `HDNodeWallet.fromPhrase`) — m/44'/60'/0'/0/i del mnemónico estándar.
//!   - HD Solana: `bip_utils` SLIP-0010 ed25519, path de Phantom
//!     m/44'/501'/i'/0' — la address 0 es la documentada de Phantom.
//!   - SLIP-0010: vectores del documento oficial (seed 000102…0f), ambas curvas.
//!   - Algorand 25 palabras: `py-algorand-sdk` (oficial) `mnemonic.from_private_key`.
//!   - Keystore V3: `eth-keyfile` (la lib Geth-compat oficial en Python) —
//!     pbkdf2 c=16384 y scrypt n=4096, password "testpassword".
//!   - PDA/ATA/SPL: `solders` (bindings del SDK Rust oficial de Solana)
//!     `Pubkey.find_program_address` + `Message.new_with_blockhash`.
//!
//! ```text
//! # gen_vectors.py (resumen; SDKs: mnemonic, eth-account, bip_utils, solders,
//! # py-algorand-sdk, eth-keyfile)
//! Mnemonic("english").to_mnemonic(entropy); Mnemonic.to_seed(phrase, "TREZOR")
//! Account.from_mnemonic(STD, account_path="m/44'/60'/0'/0/0")
//! Bip32Slip10Ed25519.FromSeed(seed).DerivePath("m/44'/501'/0'/0'")
//! algosdk.mnemonic.from_private_key(base64(seed32+pub))
//! eth_keyfile.create_keyfile_json(key, b"testpassword", kdf=..., iterations=...)
//! Pubkey.find_program_address([...], program); Message.new_with_blockhash(...)
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::bytesutil::{hex_decode, hex_encode};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{
    syn_bytes, syn_int, syn_list, syn_map, syn_secret, syn_secret_bytes, syn_text, SynValue,
};
use synsema_stdlib::blockchain::register_blockchain_builtins;
use synsema_stdlib::hashing::register_hash_builtins;
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

// -- El mnemónico estándar de test y sus derivados (eth-account / bip_utils) --
const STD_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const STD_SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
/// eth-account: (path, address EIP-55, clave privada hex).
const HD_ETH: [(&str, &str, &str); 3] = [
    ("m/44'/60'/0'/0/0", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
     "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"),
    ("m/44'/60'/0'/0/1", "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
     "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6"),
    ("m/44'/60'/0'/0/2", "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
     "5b824bd1104617939cd07c117ddc4301eb5beeca0904f964158963d69ab9d831"),
];
/// bip_utils SLIP-0010 (path Phantom): (path, clave, pubkey hex).
const HD_SOL: [(&str, &str, &str); 2] = [
    ("m/44'/501'/0'/0'", "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
     "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7"),
    ("m/44'/501'/1'/0'", "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4",
     "f8029acf5cbcbdd5ac46ec147f3b78a3df6e5022ef0411db2bab650d329a4cd4"),
];

/// Aísla el audit (wallet.log/sign.log/reveal.log) a un temp por proceso — NO se
/// suprime (custodia sin registro = pérdida de seguridad), sólo se redirige.
static AUDIT_ISOLATE: std::sync::Once = std::sync::Once::new();
fn isolate_audit_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("syn_test_audit_{}", std::process::id()));
    AUDIT_ISOLATE.call_once(|| {
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
    });
    dir
}

/// Intérprete con hashing + blockchain (incl. HD) + secrets, y un CapabilitySet
/// con `wallet` (wildcard), `reveal` (para INSPECCIONAR los secrets en el test —
/// el camino gateado+auditado legítimo) y `sign` wildcard.
fn interp_full() -> Interpreter {
    isolate_audit_dir();
    let interp = Interpreter::new();
    register_hash_builtins(&interp);
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    {
        let mut c = caps.borrow_mut();
        c.grant(Capability::new(CapabilityType::Wallet, None));
        c.grant(Capability::new(CapabilityType::Reveal, None));
        c.grant(Capability::new(CapabilityType::Sign, None));
    }
    register_secret_builtins(&interp, caps.clone(), Rc::new(EnvStore::empty()));
    register_blockchain_builtins(&interp, caps);
    interp
}

/// Intérprete SIN la capability `wallet` (deny-by-default de G20).
fn interp_no_wallet() -> Interpreter {
    isolate_audit_dir();
    let interp = Interpreter::new();
    register_hash_builtins(&interp);
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    register_blockchain_builtins(&interp, caps);
    interp
}

fn call(interp: &mut Interpreter, name: &str, args: Vec<SynValue>) -> Result<SynValue, Control> {
    let f = interp
        .global_env
        .borrow()
        .bindings
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("builtin {} no registrado", name));
    interp.call_task(f, args)
}

/// Desenvuelve un Ok con panic legible (Control no implementa Debug).
fn ok(r: Result<SynValue, Control>) -> SynValue {
    match r {
        Ok(v) => v,
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn ok_text(r: Result<SynValue, Control>) -> String {
    match ok(r) {
        SynValue::Text(s) => s.to_string(),
        other => panic!("esperaba text, got {}", other.type_name()),
    }
}

fn ok_bytes(r: Result<SynValue, Control>) -> Vec<u8> {
    match ok(r) {
        SynValue::Bytes(b) => b[..].to_vec(),
        other => panic!("esperaba bytes, got {}", other.type_name()),
    }
}

/// El valor DEBE ser un secret (G19).
fn ok_secret(r: Result<SynValue, Control>) -> SynValue {
    match ok(r) {
        v @ SynValue::Secret(_) => v,
        other => panic!(
            "G19 ROTO: esperaba un secret, el builtin devolvió {} — material de clave materializado",
            other.type_name()
        ),
    }
}

/// Extrae el plaintext por el ÚNICO camino legítimo: `reveal()` (gateado+auditado).
fn reveal_text(interp: &mut Interpreter, s: &SynValue) -> String {
    ok_text(call(interp, "reveal", vec![s.clone()]))
}

fn reveal_bytes(interp: &mut Interpreter, s: &SynValue) -> Vec<u8> {
    ok_bytes(call(interp, "reveal", vec![s.clone()]))
}

fn err_msg(r: Result<SynValue, Control>) -> String {
    match r {
        Err(Control::Error(e)) => e.message,
        Ok(v) => panic!("esperaba error, obtuve {}", v.type_name()),
        Err(_) => panic!("control inesperado"),
    }
}

fn hx(s: &str) -> Vec<u8> {
    hex_decode(s).expect("hex de test válido")
}

// =========================================================
// BIP-39 — vectores canónicos de Trezor
// =========================================================

/// (entropy, frase, seed con passphrase "TREZOR") — trezor/python-mnemonic.
const TREZOR: [(&str, &str, &str); 4] = [
    ("00000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank yellow",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
    ("0c1e24e5917779d297e14d45f14e1a1a",
     "army van defense carry jealous true garbage claim echo media make crunch",
     "3338a6d2ee71c7f28eb5b882159634cd46a898463e9d2d0980f8e80dfbba5b0fa0291e5fb888a599b44b93187be6ee3ab5fd3ead7dd646341b2cdb8d08d13bf7"),
    ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
     "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
     "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"),
];

#[test]
fn bip39_trezor_vectors_entropy_phrase_seed() {
    let mut i = interp_full();
    for (ent, phrase, seed) in TREZOR {
        // entropy → frase (mnemonic_from_entropy)
        let m = ok_secret(call(&mut i, "mnemonic_from_entropy",
            vec![syn_secret_bytes("ENT", hx(ent))]));
        assert_eq!(reveal_text(&mut i, &m), phrase, "entropy {} → frase", ent);
        // frase → seed con passphrase "TREZOR"
        let seed_s = ok_secret(call(&mut i, "mnemonic_to_seed",
            vec![m.clone(), syn_secret("PASS", "TREZOR")]));
        assert_eq!(hex_encode(&reveal_bytes(&mut i, &seed_s)), seed, "seed de {:?}", ent);
        // frase → entropy (round-trip)
        let back = ok_secret(call(&mut i, "mnemonic_to_entropy", vec![m]));
        assert_eq!(hex_encode(&reveal_bytes(&mut i, &back)), ent, "round-trip entropy");
    }
}

#[test]
fn bip39_std_mnemonic_seed_no_passphrase() {
    let mut i = interp_full();
    let m = syn_secret("MNEMONIC", STD_MNEMONIC);
    let seed = ok_secret(call(&mut i, "mnemonic_to_seed", vec![m]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &seed)), STD_SEED);
    // El name del secret derivado nombra su origen (para el scope de wallet/sign).
    assert_eq!(format!("{}", seed), "secret(MNEMONIC.seed)");
}

#[test]
fn bip39_bad_checksum_and_bad_words_error_without_leaking() {
    let mut i = interp_full();
    // "about about" al final rompe el checksum (frase con palabras válidas).
    let broken =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about about";
    let e = err_msg(call(&mut i, "mnemonic_to_seed", vec![syn_secret("M", broken)]));
    assert!(e.contains("checksum"), "debe nombrar el checksum: {}", e);
    assert!(!e.contains("abandon"), "el error NO ecoa palabras del mnemónico: {}", e);
    // Palabra fuera de la wordlist → índice, no la palabra.
    let e2 = err_msg(call(&mut i, "mnemonic_to_seed",
        vec![syn_secret("M", "zzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]));
    assert!(e2.contains("word 1"), "señala el índice: {}", e2);
    assert!(!e2.contains("zzzz"), "no ecoa la palabra desconocida: {}", e2);
    // Conteo inválido.
    let e3 = err_msg(call(&mut i, "mnemonic_to_seed", vec![syn_secret("M", "abandon abandon")]));
    assert!(e3.contains("word count"), "{}", e3);
}

#[test]
fn mnemonic_generate_is_random_valid_and_sized() {
    let mut i = interp_full();
    let a = ok_secret(call(&mut i, "mnemonic_generate", vec![]));
    let b = ok_secret(call(&mut i, "mnemonic_generate", vec![]));
    let ta = reveal_text(&mut i, &a);
    let tb = reveal_text(&mut i, &b);
    assert_ne!(ta, tb, "dos generaciones no pueden coincidir (entropía real)");
    assert_eq!(ta.split_whitespace().count(), 12, "default 12 palabras");
    // 24 palabras a pedido, y la frase generada VALIDA (checksum) → produce seed.
    let c = ok_secret(call(&mut i, "mnemonic_generate", vec![syn_int(24)]));
    assert_eq!(reveal_text(&mut i, &c).split_whitespace().count(), 24);
    ok_secret(call(&mut i, "mnemonic_to_seed", vec![c]));
    // Conteo inválido → error claro.
    let e = err_msg(call(&mut i, "mnemonic_generate", vec![syn_int(13)]));
    assert!(e.contains("12, 15, 18, 21 or 24"), "{}", e);
}

// =========================================================
// hd_derive — ETH (BIP-32) y Solana (SLIP-0010) contra SDKs
// =========================================================

#[test]
fn hd_derive_eth_matches_eth_account_vectors() {
    let mut i = interp_full();
    let seed = ok_secret(call(&mut i, "mnemonic_to_seed",
        vec![syn_secret("MNEMONIC", STD_MNEMONIC)]));
    for (path, address, key) in HD_ETH {
        let k = ok_secret(call(&mut i, "hd_derive", vec![seed.clone(), syn_text(path)]));
        assert_eq!(hex_encode(&reveal_bytes(&mut i, &k)), key, "clave de {}", path);
        // La clave derivada se usa DIRECTO con eth_address (sin materializarse).
        assert_eq!(ok_text(call(&mut i, "eth_address", vec![k])), address,
            "address EIP-55 de {}", path);
    }
}

#[test]
fn hd_derive_solana_matches_phantom_path_vectors() {
    let mut i = interp_full();
    let seed = ok_secret(call(&mut i, "mnemonic_to_seed",
        vec![syn_secret("MNEMONIC", STD_MNEMONIC)]));
    for (path, key, pubkey) in HD_SOL {
        let k = ok_secret(call(&mut i, "hd_derive",
            vec![seed.clone(), syn_text(path), syn_text("ed25519")]));
        assert_eq!(hex_encode(&reveal_bytes(&mut i, &k)), key, "clave de {}", path);
        let pk = ok_bytes(call(&mut i, "ed25519_pubkey", vec![k]));
        assert_eq!(hex_encode(&pk), pubkey, "pubkey de {}", path);
    }
    // La address 0 en base58 es la de Phantom (documentada):
    let k0 = ok_secret(call(&mut i, "hd_derive",
        vec![seed, syn_text("m/44'/501'/0'/0'"), syn_text("ed25519")]));
    let pk0 = ok_bytes(call(&mut i, "ed25519_pubkey", vec![k0]));
    assert_eq!(
        synsema_core::bytesutil::base58_encode(&pk0),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
}

/// Vectores del documento OFICIAL SLIP-0010 (seed 000102030405060708090a0b0c0d0e0f).
#[test]
fn hd_derive_slip10_official_vectors_both_curves() {
    let mut i = interp_full();
    let seed = syn_secret_bytes("S", hx("000102030405060708090a0b0c0d0e0f"));
    // secp256k1 (== BIP-32 test vector 1)
    let master = ok_secret(call(&mut i, "hd_derive", vec![seed.clone(), syn_text("m")]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &master)),
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    let k = ok_secret(call(&mut i, "hd_derive",
        vec![seed.clone(), syn_text("m/0'/1/2'/2/1000000000")]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &k)),
        "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8");
    // ed25519 (hardened-only)
    let em = ok_secret(call(&mut i, "hd_derive",
        vec![seed.clone(), syn_text("m"), syn_text("ed25519")]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &em)),
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
    let ek = ok_secret(call(&mut i, "hd_derive",
        vec![seed, syn_text("m/0'/1'/2'/2'/1000000000'"), syn_text("ed25519")]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &ek)),
        "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793");
}

#[test]
fn hd_derive_hostile_paths_error_catchable_g18() {
    let mut i = interp_full();
    let seed = syn_secret_bytes("S", hx(STD_SEED));
    // ed25519 con índice no-hardened → error dirigido.
    let e = err_msg(call(&mut i, "hd_derive",
        vec![seed.clone(), syn_text("m/44'/501'/0'/0"), syn_text("ed25519")]));
    assert!(e.contains("HARDENED"), "{}", e);
    // Basura, path larguísimo y con miles de segmentos → error atrapable, no cuelgue.
    let mut bads: Vec<String> = ["banana", "m/xx", "m/-1", "m/2147483648", "m//0"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    bads.push(format!("m{}", "/1'".repeat(50))); // 50 > PATH_MAX_SEGMENTS
    bads.push(format!("m/{}", "9".repeat(300))); // > 256 chars
    bads.push(format!("m{}", "/0".repeat(5000))); // hostil de verdad
    for bad in &bads {
        let e = err_msg(call(&mut i, "hd_derive", vec![seed.clone(), syn_text(bad.as_str())]));
        assert!(e.contains("hd_derive"), "error atrapable para {:?}: {}", bad, e);
    }
    // Curva desconocida.
    let e = err_msg(call(&mut i, "hd_derive",
        vec![seed, syn_text("m/0"), syn_text("curve9000")]));
    assert!(e.contains("secp256k1"), "{}", e);
}

// =========================================================
// Algorand — 25 palabras contra algosdk
// =========================================================

/// algosdk: seed 000102…1f → frase de 25 palabras + address.
const ALGO_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ALGO_MNEMONIC: &str = "cactus amount account expect army achieve embark anxiety lift crouch mandate abstract captain setup party bench tissue gate arrive random deal mansion wedding abandon curtain";
const ALGO_ADDR: &str = "AOQQPP7TZYIL4HLQ3UMOOS6ATFT6JVRQTOSQ2XY53SDGIESVGG4MPFYUMQ";
/// Segundo vector: la seed RFC 8032 TEST 2 (la de los batches 11/12).
const ALGO_SEED2: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const ALGO_MNEMONIC2: &str = "praise case eternal verb combine issue reject senior match element poem rail believe small provide private network hammer edit term panther puppy tag abstract bone";

#[test]
fn algorand_25_words_matches_algosdk_roundtrip() {
    let mut i = interp_full();
    for (seed, phrase) in [(ALGO_SEED, ALGO_MNEMONIC), (ALGO_SEED2, ALGO_MNEMONIC2)] {
        let k = syn_secret_bytes("ALGO_KEY", hx(seed));
        let m = ok_secret(call(&mut i, "algorand_mnemonic", vec![k]));
        assert_eq!(reveal_text(&mut i, &m), phrase, "frase de {}", seed);
        let back = ok_secret(call(&mut i, "algorand_mnemonic_to_key", vec![m]));
        assert_eq!(hex_encode(&reveal_bytes(&mut i, &back)), seed, "round-trip");
    }
    // La clave recuperada deriva la address de algosdk (la frase carga en Pera/Defly).
    let m = ok_secret(call(&mut i, "algorand_mnemonic",
        vec![syn_secret_bytes("K", hx(ALGO_SEED))]));
    let k = ok_secret(call(&mut i, "algorand_mnemonic_to_key", vec![m]));
    assert_eq!(ok_text(call(&mut i, "algo_address", vec![k])), ALGO_ADDR);
}

#[test]
fn algorand_mnemonic_bad_checksum_and_shape_error_without_leaking() {
    let mut i = interp_full();
    // Intercambiar dos palabras rompe el checksum.
    let mut words: Vec<&str> = ALGO_MNEMONIC.split(' ').collect();
    words.swap(0, 1);
    let swapped = words.join(" ");
    let e = err_msg(call(&mut i, "algorand_mnemonic_to_key",
        vec![syn_secret("M", swapped)]));
    assert!(e.contains("checksum"), "{}", e);
    assert!(!e.contains("cactus"), "no ecoa palabras: {}", e);
    // 24 palabras (le falta una) → error de conteo que aclara que NO es BIP-39.
    let short = ALGO_MNEMONIC.rsplit_once(' ').unwrap().0;
    let e2 = err_msg(call(&mut i, "algorand_mnemonic_to_key", vec![syn_secret("M", short)]));
    assert!(e2.contains("25 words"), "{}", e2);
    // Una clave que no es de 32 bytes → error de forma.
    let e3 = err_msg(call(&mut i, "algorand_mnemonic",
        vec![syn_secret_bytes("K", vec![1, 2, 3])]));
    assert!(e3.contains("32-byte"), "{}", e3);
}

// =========================================================
// Keystore V3 — eth-keyfile (Geth-compat oficial)
// =========================================================

const KS_KEY: &str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
const KS_ADDR: &str = "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b";
const KS_PBKDF2: &str = r#"{"address": "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b", "crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": "65feedf1e103d954c4d63b09e56f28cb"}, "ciphertext": "1cf0ab0a1922aab254489b2d137f347b33324d338b89da8e20d618597099beb8", "kdf": "pbkdf2", "kdfparams": {"c": 16384, "dklen": 32, "prf": "hmac-sha256", "salt": "1b045c612f5073812fbdc5268e290f96"}, "mac": "80ca118d91312a2cd26ebfc462f03b092609cc72911ad1c8b70a5197540d3bf6"}, "id": "60cf9c94-f23b-4c85-a36f-5f0abd5968b2", "version": 3}"#;
const KS_SCRYPT: &str = r#"{"address": "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b", "crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": "c3b2f652c64e4d835d02d085d2694eeb"}, "ciphertext": "baafc1142e03c178f44582e6ea3127c892226514105795a5e5e6328b0d3b1af2", "kdf": "scrypt", "kdfparams": {"dklen": 32, "n": 4096, "r": 8, "p": 1, "salt": "ccd94029026bd5e0b5f102c1fc129d3a"}, "mac": "1dcb819fba8327856d8e658a782f8b215a66d0ec9868495a4ed84adf4f54bea3"}, "id": "78698212-8f2a-4259-b2e8-097b4f290848", "version": 3}"#;

#[test]
fn keystore_import_pbkdf2_and_scrypt_match_eth_keyfile() {
    let mut i = interp_full();
    for (ks, kdf) in [(KS_PBKDF2, "pbkdf2"), (KS_SCRYPT, "scrypt")] {
        let k = ok_secret(call(&mut i, "keystore_import",
            vec![syn_text(ks), syn_secret("PASS", "testpassword")]));
        assert_eq!(hex_encode(&reveal_bytes(&mut i, &k)), KS_KEY, "clave via {}", kdf);
        assert_eq!(ok_text(call(&mut i, "eth_address", vec![k])), KS_ADDR,
            "address via {}", kdf);
    }
}

#[test]
fn keystore_wrong_passphrase_fails_without_material() {
    let mut i = interp_full();
    let e = err_msg(call(&mut i, "keystore_import",
        vec![syn_text(KS_PBKDF2), syn_secret("PASS", "nottherightone")]));
    assert!(e.contains("wrong passphrase"), "{}", e);
    assert!(!e.to_lowercase().contains(&KS_KEY[..16]), "sin material en el error: {}", e);
}

#[test]
fn keystore_hostile_kdf_params_rejected_fast() {
    let mut i = interp_full();
    // n gigante (2^30 · r=8) — OOM/cuelgue si no se acota. Debe errar RÁPIDO.
    let hostile = KS_SCRYPT.replace("\"n\": 4096", "\"n\": 1073741824");
    let t0 = std::time::Instant::now();
    let e = err_msg(call(&mut i, "keystore_import",
        vec![syn_text(hostile.as_str()), syn_secret("PASS", "x")]));
    assert!(t0.elapsed() < std::time::Duration::from_secs(2), "debe rechazar sin computar");
    assert!(e.contains("out of the accepted range"), "{}", e);
    // n no potencia de dos.
    let odd = KS_SCRYPT.replace("\"n\": 4096", "\"n\": 4095");
    let e2 = err_msg(call(&mut i, "keystore_import",
        vec![syn_text(odd.as_str()), syn_secret("PASS", "x")]));
    assert!(e2.contains("power of two"), "{}", e2);
    // c gigante en pbkdf2.
    let hostile_c = KS_PBKDF2.replace("\"c\": 16384", "\"c\": 999999999");
    let e3 = err_msg(call(&mut i, "keystore_import",
        vec![syn_text(hostile_c.as_str()), syn_secret("PASS", "x")]));
    assert!(e3.contains("out of the accepted range"), "{}", e3);
    // Versión no soportada.
    let v4 = KS_PBKDF2.replace("\"version\": 3", "\"version\": 4");
    let e4 = err_msg(call(&mut i, "keystore_import",
        vec![syn_text(v4.as_str()), syn_secret("PASS", "x")]));
    assert!(e4.contains("version 3"), "{}", e4);
}

#[test]
fn keystore_export_roundtrip_and_v3_shape() {
    let mut i = interp_full();
    let key = syn_secret_bytes("HOT", hx(KS_KEY));
    // scrypt liviano para que el test vuele; el default (sin opts) es n=262144 (Geth).
    let mut opts = indexmap::IndexMap::new();
    opts.insert("kdf".to_string(), syn_text("scrypt"));
    opts.insert("n".to_string(), syn_int(1024));
    let json = ok_text(call(&mut i, "keystore_export",
        vec![key.clone(), syn_secret("PASS", "s3cret"), syn_map(opts)]));
    let doc: serde_json::Value = serde_json::from_str(&json).expect("JSON válido");
    assert_eq!(doc["version"], 3);
    assert_eq!(doc["crypto"]["cipher"], "aes-128-ctr");
    assert_eq!(doc["crypto"]["kdf"], "scrypt");
    assert_eq!(doc["address"], KS_ADDR[2..].to_lowercase(), "address minúscula sin 0x (Geth)");
    assert!(!json.contains(KS_KEY), "el JSON exportado JAMÁS contiene la clave en claro");
    // Round-trip: import de lo exportado → la misma clave.
    let back = ok_secret(call(&mut i, "keystore_import",
        vec![syn_text(json.as_str()), syn_secret("PASS", "s3cret")]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &back)), KS_KEY);
    // Passphrase equivocada sobre lo exportado → error sin material.
    let e = err_msg(call(&mut i, "keystore_import",
        vec![syn_text(json.as_str()), syn_secret("PASS", "wrong")]));
    assert!(e.contains("wrong passphrase"), "{}", e);
    // pbkdf2 export round-trip.
    let mut opts2 = indexmap::IndexMap::new();
    opts2.insert("kdf".to_string(), syn_text("pbkdf2"));
    opts2.insert("c".to_string(), syn_int(2048));
    let json2 = ok_text(call(&mut i, "keystore_export",
        vec![key, syn_secret("PASS", "s3cret"), syn_map(opts2)]));
    let back2 = ok_secret(call(&mut i, "keystore_import",
        vec![syn_text(json2.as_str()), syn_secret("PASS", "s3cret")]));
    assert_eq!(hex_encode(&reveal_bytes(&mut i, &back2)), KS_KEY);
}

// =========================================================
// G19 estructural + G20 gate/audit
// =========================================================

#[test]
fn g19_secrets_redact_and_never_materialize() {
    let mut i = interp_full();
    let m = ok_secret(call(&mut i, "mnemonic_generate", vec![]));
    // Display/Debug redactan (lo que vería print/log/format).
    assert_eq!(format!("{}", m), "secret(mnemonic)");
    assert!(format!("{:?}", m).contains("mnemonic"));
    assert!(!format!("{:?}", m).contains("abandon"), "Debug jamás muestra la frase");
    let seed = ok_secret(call(&mut i, "mnemonic_to_seed", vec![m]));
    assert_eq!(format!("{}", seed), "secret(mnemonic.seed)");
    let k = ok_secret(call(&mut i, "hd_derive", vec![seed, syn_text("m/44'/60'/0'/0/0")]));
    assert!(format!("{}", k).starts_with("secret("));
    // hashear un secret está prohibido (no hay canal de extracción por hash).
    let e = err_msg(call(&mut i, "sha256", vec![k]));
    assert!(e.contains("secret"), "{}", e);
}

#[test]
fn g20_wallet_gate_denies_by_default_and_audits() {
    let dir = isolate_audit_dir();
    let mut i = interp_no_wallet();
    let cases: Vec<(&str, Vec<SynValue>)> = vec![
        ("mnemonic_generate", vec![]),
        ("mnemonic_to_seed", vec![syn_secret("M", STD_MNEMONIC)]),
        ("hd_derive", vec![syn_secret_bytes("S", hx(STD_SEED)), syn_text("m/0")]),
        ("algorand_mnemonic", vec![syn_secret_bytes("K", hx(ALGO_SEED))]),
        ("algorand_mnemonic_to_key", vec![syn_secret("M", ALGO_MNEMONIC)]),
        ("keystore_import", vec![syn_text(KS_PBKDF2), syn_secret("P", "x")]),
        ("keystore_export", vec![syn_secret_bytes("K", hx(KS_KEY)), syn_secret("P", "x")]),
        ("mnemonic_from_entropy",
         vec![syn_secret_bytes("E", hx("00000000000000000000000000000000"))]),
        ("mnemonic_to_entropy", vec![syn_secret("M", STD_MNEMONIC)]),
    ];
    for (builtin, args) in cases {
        let e = err_msg(call(&mut i, builtin, args));
        assert!(
            e.contains("wallet not permitted") && e.contains("require wallet"),
            "{} debe denegar sin `wallet` y sugerir el fix: {}",
            builtin,
            e
        );
    }
    // El intento denegado quedó auditado; una creación concedida también.
    let mut ok_i = interp_full();
    ok_secret(call(&mut ok_i, "mnemonic_generate", vec![syn_int(12), syn_text("AUDITME")]));
    let log = std::fs::read_to_string(dir.join("wallet.log")).expect("wallet.log existe");
    assert!(log.contains("wallet op=generate result=denied"), "audita el deny: {}", log);
    assert!(
        log.contains("wallet op=generate result=granted name=AUDITME"),
        "audita el grant: {}",
        log
    );
    assert!(!log.contains("abandon"), "el audit JAMÁS contiene material");
}

#[test]
fn g20_wallet_scope_is_the_source_secret_name() {
    isolate_audit_dir();
    // wallet("MNEMONIC*") scoped: permite derivar DESDE ese mnemónico y su seed
    // (glob del prefijo), pero no desde otros.
    let interp = Interpreter::new();
    register_hash_builtins(&interp);
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    caps.borrow_mut()
        .grant(Capability::new(CapabilityType::Wallet, Some("MNEMONIC*".into())));
    register_blockchain_builtins(&interp, caps);
    let mut i = interp;
    let seed = ok_secret(call(&mut i, "mnemonic_to_seed",
        vec![syn_secret("MNEMONIC", STD_MNEMONIC)]));
    ok_secret(call(&mut i, "hd_derive", vec![seed, syn_text("m/0")]));
    // Otro secret fuera del scope → denegado (anti-swap: el scope evalúa el name real).
    let e = err_msg(call(&mut i, "mnemonic_to_seed", vec![syn_secret("OTRA", STD_MNEMONIC)]));
    assert!(e.contains("wallet not permitted"), "{}", e);
}

// =========================================================
// Solana PDA / ATA / SPL — vectores de solders
// =========================================================

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const PDA_HEX: &str = "2e59702b1a38066737b4e6c27e78c5fbe48ed53ca651087293b6626acb696d10";
const ATA_HEX: &str = "9958db38c3bb8bf04f6da81d59d3e34f7e17de3ec94b885e2d79050e75ff3f6e";
const DEST_ATA_HEX: &str = "6dd77f9e065e224f08206f15f6406539bd061598f266658d7b86ac026f194f00";
const SPL_MSG_HEX: &str = "0100020502020202020202020202020202020202020202020202020202020202020202026dd77f9e065e224f08206f15f6406539bd061598f266658d7b86ac026f194f009958db38c3bb8bf04f6da81d59d3e34f7e17de3ec94b885e2d79050e75ff3f6e030303030303030303030303030303030303030303030303030303030303030306ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90707070707070707070707070707070707070707070707070707070707070707010404020301000a0c40420f000000000006";

#[test]
fn solana_pda_matches_solders_find_program_address() {
    let mut i = interp_full();
    let pda = ok(call(&mut i, "solana_pda", vec![
        syn_list(vec![
            syn_text("metadata"),
            syn_bytes(synsema_core::bytesutil::base58_decode(TOKEN_PROGRAM).unwrap()),
            syn_bytes(vec![3u8; 32]),
        ]),
        syn_text(TOKEN_PROGRAM),
    ]));
    match pda {
        SynValue::Map(m) => {
            let m = m.borrow();
            match (m.get("address"), m.get("bump")) {
                (Some(SynValue::Bytes(a)), Some(bump)) => {
                    assert_eq!(hex_encode(a), PDA_HEX, "PDA contra solders");
                    assert_eq!(bump.to_string(), "254", "bump contra solders");
                }
                other => panic!("mapa PDA incompleto: {:?}",
                    other.0.map(|v| v.type_name())),
            }
        }
        other => panic!("esperaba map, got {}", other.type_name()),
    }
}

#[test]
fn spl_ata_matches_solders() {
    let mut i = interp_full();
    let ata = ok_bytes(call(&mut i, "spl_ata",
        vec![syn_bytes(vec![2u8; 32]), syn_bytes(vec![3u8; 32])]));
    assert_eq!(hex_encode(&ata), ATA_HEX, "ATA contra solders");
    let dest = ok_bytes(call(&mut i, "spl_ata",
        vec![syn_bytes(vec![4u8; 32]), syn_bytes(vec![3u8; 32])]));
    assert_eq!(hex_encode(&dest), DEST_ATA_HEX);
}

#[test]
fn spl_transfer_instruction_data_layout() {
    // Layout del Token Program (fuente: spl-token program, TokenInstruction):
    // Transfer = tag 3 ‖ amount u64 LE; TransferChecked = tag 12 ‖ amount ‖ decimals.
    let mut i = interp_full();
    let t = ok_bytes(call(&mut i, "spl_transfer_data", vec![syn_int(1_000_000)]));
    assert_eq!(hex_encode(&t), "0340420f0000000000");
    let tc = ok_bytes(call(&mut i, "spl_transfer_checked_data",
        vec![syn_int(1_000_000), syn_int(6)]));
    assert_eq!(hex_encode(&tc), "0c40420f000000000006",
        "byte a byte contra el ix data de solders");
}

#[test]
fn spl_transfer_full_message_matches_solders() {
    // El transfer SPL COMPLETO: spl_ata + spl_transfer_checked_data + solana_message
    // reproducen byte a byte el Message.new_with_blockhash de solders.
    let mut i = interp_full();
    let owner = syn_bytes(vec![2u8; 32]);
    let mint = syn_bytes(vec![3u8; 32]);
    let src = ok(call(&mut i, "spl_ata", vec![owner.clone(), mint.clone()]));
    let dst = ok(call(&mut i, "spl_ata", vec![syn_bytes(vec![4u8; 32]), mint.clone()]));
    let data = ok(call(&mut i, "spl_transfer_checked_data",
        vec![syn_int(1_000_000), syn_int(6)]));
    let account = |pk: SynValue, signer: bool, writable: bool| {
        let mut m = indexmap::IndexMap::new();
        m.insert("pubkey".to_string(), pk);
        m.insert("signer".to_string(), SynValue::Bool(signer));
        m.insert("writable".to_string(), SynValue::Bool(writable));
        syn_map(m)
    };
    let mut ix = indexmap::IndexMap::new();
    ix.insert("program".to_string(), syn_text(TOKEN_PROGRAM));
    ix.insert("accounts".to_string(), syn_list(vec![
        account(src, false, true),
        account(mint, false, false),
        account(dst, false, true),
        account(owner.clone(), true, false),
    ]));
    ix.insert("data".to_string(), data);
    let mut params = indexmap::IndexMap::new();
    params.insert("fee_payer".to_string(), owner);
    params.insert("recent_blockhash".to_string(), syn_bytes(vec![7u8; 32]));
    params.insert("instructions".to_string(), syn_list(vec![syn_map(ix)]));
    let msg = ok_bytes(call(&mut i, "solana_message", vec![syn_map(params)]));
    assert_eq!(hex_encode(&msg), SPL_MSG_HEX, "transfer SPL byte a byte contra solders");
}

// =========================================================
// G18 — descenso acotado sobre input hostil (thread de stack grande)
// =========================================================

#[test]
fn g18_hostile_deep_input_errors_never_overflows() {
    // El batch 13 no agrega un descenso recursivo NUEVO (el path parser es
    // iterativo y acotado; el keystore usa serde_json con su propio límite). Este
    // guard lo PRUEBA con estructura hostil, en un thread de stack grande (el mismo
    // método del batch 12: construir el input hostil no debe requerir, ni el
    // parsearlo desbordar, un stack chico). Un abort no atrapable = DoS bajo serve.
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut i = interp_full();
            // 1) Path de derivación absurdamente largo y con miles de segmentos.
            let deep_path = format!("m{}", "/0".repeat(100_000));
            let e = err_msg(call(&mut i, "hd_derive",
                vec![syn_secret_bytes("S", hx(STD_SEED)), syn_text(deep_path.as_str())]));
            assert!(e.contains("hd_derive"), "path hostil → error atrapable: {}", e);
            // 2) Keystore con JSON anidado a lo bestia → serde_json lo rechaza,
            //    jamás desborda el stack.
            let deep_json = format!("{}{}", "{\"crypto\":".repeat(100_000), "1".to_string()
                + &"}".repeat(100_000));
            let e2 = err_msg(call(&mut i, "keystore_import",
                vec![syn_text(deep_json.as_str()), syn_secret("P", "x")]));
            assert!(e2.contains("keystore_import"), "JSON hostil → error atrapable: {}", e2);
            // 3) solana_pda con una lista de seeds hostil (aunque acotada a 15, el
            //    parser no debe romperse ante muchos elementos previos al chequeo).
            let many: Vec<SynValue> = (0..10_000).map(|_| syn_bytes(vec![1u8])).collect();
            let e3 = err_msg(call(&mut i, "solana_pda",
                vec![syn_list(many), syn_text(TOKEN_PROGRAM)]));
            assert!(e3.contains("max 15"), "muchos seeds → error acotado: {}", e3);
        })
        .expect("spawn big-stack thread");
    handle.join().expect("el guard G18 no debe entrar en panic/abort");
}

#[test]
fn solana_pda_hostile_inputs_error_catchable() {
    let mut i = interp_full();
    // Seed > 32 bytes.
    let e = err_msg(call(&mut i, "solana_pda", vec![
        syn_list(vec![syn_bytes(vec![0u8; 33])]), syn_text(TOKEN_PROGRAM)]));
    assert!(e.contains("max 32"), "{}", e);
    // Más de 15 seeds.
    let many: Vec<SynValue> = (0..16).map(|_| syn_bytes(vec![1u8])).collect();
    let e2 = err_msg(call(&mut i, "solana_pda",
        vec![syn_list(many), syn_text(TOKEN_PROGRAM)]));
    assert!(e2.contains("max 15"), "{}", e2);
    // Un secret como seed → error dirigido (los seeds son públicos).
    let e3 = err_msg(call(&mut i, "solana_pda", vec![
        syn_list(vec![syn_secret("K", "x")]), syn_text(TOKEN_PROGRAM)]));
    assert!(e3.contains("PUBLIC"), "{}", e3);
}

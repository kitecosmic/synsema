//! v0.6.60 (texto para tokenizadores) desde un programa, fila por fila de las tablas de casos de
//! `specs/v0.6.60-texto-diseno.md`: A (normalización: `nfc`, `nfd`, `nfkc`, `nfkd`), B (regex con
//! retroceso: `backtrack_*`, y las `regex_*` que guardan sus compilados) y C (`to_list(bytes)`).
//!
//! Los esperados de A coinciden con `unicodedata.normalize` de Python 3.12; los de B, con el
//! iterador de `fancy-regex` 0.20.2 con el parche de `engine/vendor/fancy-regex`; los de las `regex_*`, con lo que
//! imprime el binario v0.6.59.
//!
//! Los caracteres que importan van con su escape (`é`), no escritos: un editor que normalice
//! el archivo no puede cambiar lo que el test prueba.

fn run(src: &str) -> synsema_core::interpreter::RunResult {
    synsema_runtime::engine::run_source(src, "v0660.syn")
}

/// Lo impreso por el programa, o `ERR: <error>`.
fn out(src: &str) -> String {
    let r = run(src);
    if r.success {
        r.output.join("\n")
    } else {
        format!("ERR: {}", r.errors.join("\n"))
    }
}

fn eq(src: &str, want: &str) {
    assert_eq!(out(src), want, "{}", src);
}

fn err_has(src: &str, want: &str) {
    let got = out(src);
    assert!(got.starts_with("ERR: ") && got.contains(want), "{}\n→ {}", src, got);
}

/// Un literal de texto de Synsema con ese contenido (sólo escapa `\` y `"`).
fn lit(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

const STEP_LIMIT: &str = "step limit exceeded (max_steps = 1048576) — the pattern did more work on this text than the \
                          limit allows; if a repetition is tried again from every position of a long run (\\d+(?![\\d.]) \
                          reads a long number once from each of its digits), say where a match may start \
                          ((?<!\\d)\\d+(?![\\d.])); if it backtracks (nested or ambiguous repetitions, look-arounds inside \
                          repetitions), make repetitions possessive (a++, a*+) or atomic ((?>…)); if the work is what the \
                          pattern needs, pass a higher max_steps";
const TOO_LARGE: &str = "the compiled pattern, with the memory its searches need, is over 16 MiB: a subroutine call \
                         (\\g<1>) copies its group at every call, a counted repetition of a Unicode class (\\w{300}) is \
                         large, and capture groups multiply what a search needs (groups × size of the pattern); write it \
                         so that it repeats less, capture less ((?:…) does not capture) or use ASCII classes \
                         ([0-9A-Za-z_] for \\w), or split it into several patterns";

/// Un programa con módulos, en un directorio temporal propio (el contador hace único el nombre).
fn run_files(files: &[(&str, &str)], main: &str) -> synsema_core::interpreter::RunResult {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synsema-v0660-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src) in files {
        std::fs::write(dir.join(name), src).unwrap();
    }
    let path = dir.join("main.syn");
    std::fs::write(&path, main).unwrap();
    let r = synsema_runtime::engine::run_source(main, path.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    r
}
const LINEAR_HINT: &str = "regex_* run in linear time and have no look-around or backreferences \
                           — use backtrack_find_all, backtrack_capture, backtrack_replace or backtrack_matches";

// ---------- A: normalización ----------

#[test]
pub fn the_four_forms_from_a_program() {
    // A1, A2: las dos escrituras de `é`
    eq(r#"print("\u00e9" == "e\u0301", nfc("e\u0301") == "\u00e9", nfc("\u00e9") == "\u00e9")"#, "false true true");
    eq(r#"print(length(nfd("\u00e9")), nfd("\u00e9") == "e\u0301", length(nfc("e\u0301")))"#, "2 true 1");
    // A3, A4: compatibilidad (ligadura, ancho completo, superíndice) sólo en las K
    eq(r#"print(nfc("\ufb01") == "\ufb01", nfd("\ufb01") == "\ufb01", nfkc("\ufb01"), nfkd("\ufb01"))"#, "true true fi fi");
    eq(r#"print(nfkc("\uff21"), nfkc("x\u00b2"), nfc("x\u00b2") == "x\u00b2")"#, "A x2 true");
    // A5: hangul
    eq(
        r#"print(length(nfd("\ud55c")), nfd("\ud55c") == "\u1112\u1161\u11ab", nfc("\u1112\u1161\u11ab") == "\ud55c", nfkd("\ud55c") == nfd("\ud55c"))"#,
        "3 true true true",
    );
    // A6: un carácter que cambia aun en NFC (el signo ångström)
    eq(r#"print(nfc("\u212b") == "\u00c5", nfd("\u212b") == "A\u030a")"#, "true true");
    // A7: el caso que distingue a las cuatro
    eq(
        r#"let s be "\u1e9b\u0323"
print(nfc(s) == s, nfd(s) == "\u017f\u0323\u0307", nfkc(s) == "\u1e69", nfkd(s) == "s\u0323\u0307")"#,
        "true true true true",
    );
    // A8: orden canónico
    eq(
        r#"print(nfd("a\u0307\u0323") == nfd("a\u0323\u0307"), nfd("a\u0307\u0323") == "a\u0323\u0307", nfc("a\u0307\u0323") == "\u1ea1\u0307")"#,
        "true true true",
    );
    // A9
    eq(r#"print(nfc("") == "", nfd("hola"), nfkc("hola"), nfkd("hola"))"#, "true hola hola hola");
}

#[test]
pub fn normalized_text_compares_hashes_and_keys_as_one() {
    // A10: normalizar dos veces no cambia nada
    eq(
        r#"let ok be true
each s in ["e\u0301", "\u00e9", "\ufb01", "\u1e9b\u0323", "a\u0307\u0323", "\ud55c", "hola", ""]
    each f in [nfc, nfd, nfkc, nfkd]
        when f(f(s)) != f(s)
            set ok to false
print(ok)"#,
        "true",
    );
    // lo que la entrada de faltantes pedía: una clave de mapa y un hash
    eq(
        r#"let m be {}
set m[nfc("e\u0301")] to 1
set m[nfc("\u00e9")] to 2
print(length(keys(m)), sha256(nfc("e\u0301")) == sha256(nfc("\u00e9")), sha256("e\u0301") == sha256("\u00e9"))"#,
        "1 true false",
    );
    // A11: sacar tildes como BERT (NFD + quitar las marcas)
    eq(r#"print(regex_replace(nfd("\u00d1and\u00fa"), "\\p{Mn}", ""))"#, "Nandu");
    // con `apply`, una lista
    eq(r#"print(apply(["e\u0301", "a"], nfc) == ["\u00e9", "a"])"#, "true");
}

#[test]
pub fn normalization_takes_text_only() {
    for f in ["nfc", "nfd", "nfkc", "nfkd"] {
        // A12
        err_has(
            &format!(r#"print({}(bytes("x")))"#, f),
            &format!("{} expects text, got bytes — decode it first: {}(decode(b))", f, f),
        );
        // A13
        err_has(&format!("print({}(5))", f), &format!("{} expects text, got number", f));
        err_has(&format!("print({}(nothing))", f), &format!("{} expects text, got nothing", f));
        err_has(&format!(r#"print({}(["a"]))"#, f), &format!("{} expects text, got list", f));
        // A14
        err_has(&format!("print({}())", f), &format!("{}() needs 1 argument, got 0", f));
        err_has(&format!(r#"print({}("a", "b"))"#, f), &format!("{}() takes at most 1 argument, got 2", f));
    }
    // el arreglo que nombra el error anda
    eq(r#"print(nfc(decode(bytes("e\u0301"))) == "\u00e9")"#, "true");
    // A15: sin asignar en Unicode 15, con decomposición en Unicode 17
    eq(r#"print(nfkc("\ua7f1"), nfc("\ua7f1") == "\ua7f1")"#, "S true");
}

// ---------- B: backtrack_* ----------

#[test]
pub fn backtrack_results_have_the_shape_of_their_regex_pair() {
    // B1: el corte de espacios de GPT-2 y tiktoken
    eq(r#"print(backtrack_find_all("a   b", "\\s+(?!\\S)|\\s+"))"#, r#"["  ", " "]"#);
    // B3, B4, B5, B6
    eq(r#"print(backtrack_find_all("aXb", "(?i:x)"), backtrack_find_all("aaaa", "a++a"), regex_find_all("aaaa", "a++a"))"#, r#"["X"] [] ["aaaa"]"#);
    eq(r#"print(backtrack_find_all("aa", "(?=a)"), backtrack_find_all("AU$10, $20", "(?<=\\$)\\d+"))"#, r#"["", ""] ["10", "20"]"#);
    // los grupos no cambian lo que devuelve find_all
    eq(r#"print(backtrack_find_all("a1 b2", "([a-z])(?=\\d)(\\d)"))"#, r#"["a1", "b2"]"#);
    // B7–B10
    eq(r#"print(backtrack_capture("AU$10, $20", "(?<!AU)\\$(\\d+)"), backtrack_capture("hola", "(?<=h)ola"))"#, r#"["20"] ["ola"]"#);
    eq(r#"print(backtrack_capture("2026-09", "(\\d+)-(\\d+)(x)?(?!\\d)"), backtrack_capture("x", "y"))"#, r#"["2026", "09", nothing] nothing"#);
    // B11, B12
    eq(r#"print(backtrack_replace("ab@xy cd@zz", "(\\w+)@(?=x)(\\w+)", "\\2/\\1"))"#, "xy/ab cd@zz");
    eq(
        r#"print(backtrack_replace("ab", "a(?=b)", "$1"), backtrack_replace("ab", "a(?=b)", "[\\3]"), backtrack_replace("ab", "(\\w)(?!$)", "\\g<1>\\g<1>"), backtrack_replace("ab", "(?=x)x", "-"))"#,
        "$1b []b aab ab",
    );
    // B13
    eq(
        r#"print(backtrack_matches("abab", "(ab)\\1"), backtrack_matches("xabab", "(ab)\\1"), backtrack_matches("a\n", "a"), backtrack_matches("", "(?=a)|"))"#,
        "true false false true",
    );
}

#[test]
pub fn the_cl100k_pattern_cuts_like_tiktoken() {
    // B2
    let cl100k = r"'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|\s*[\r\n]|\s+(?!\S)|\s";
    let src = format!(
        "let trozos be backtrack_find_all(\"Hola,  mundo!\\n\\n  It's 12345 \\u00f1and\\u00fa   \", {})\nprint(trozos)\nprint(join(trozos, \"|\"))",
        lit(cl100k)
    );
    eq(
        &src,
        "[\"Hola\", \",\", \" \", \" mundo\", \"!\\n\\n\", \" \", \" It\", \"'s\", \" \", \"123\", \"45\", \" \u{f1}and\u{fa}\", \"   \"]\nHola|,| | mundo|!\n\n| | It|'s| |123|45| \u{f1}and\u{fa}|   ",
    );
    // juntar los trozos devuelve el texto: el patrón cubre todo carácter
    let src = format!(
        "let t be \"El perro come 42 veces; la perra duerme.\\n  Hello, world! It's fine.\\n\\n\"\nprint(join(backtrack_find_all(t, {}), \"\") == t)",
        lit(cl100k)
    );
    eq(&src, "true");
}

/// B14: sobre patrones que los dos motores leen igual, cada función da lo mismo que su par.
#[test]
pub fn without_lookaround_both_families_agree() {
    let patterns = [
        r"\w+", r"[0-9]+", r"\s+", r"(\w)(\d)?", r"x*", r"", r"a|b", r"(?i)h\w*", r"\p{L}+", r" ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+",
        r"^\w+", r"\w+$", r"(a)|(b)", r"\bd", r"[^\s,]+", r".", r"(?s).", r"\d{2,3}", r"(?m)^.", r"é+",
    ];
    let texts = ["", "a", "Hola,  mundo 42!", "ab cd\n12 éé", "a1 b22 c333", "   ", "ba,ab,,d d"];
    let mut src = String::from("let distintos be []\n");
    for p in patterns {
        for t in texts {
            let (t, p) = (lit(&t.replace('\n', "\u{1}")).replace('\u{1}', "\\n"), lit(p));
            for (a, b) in [
                (format!("regex_find_all({t}, {p})"), format!("backtrack_find_all({t}, {p})")),
                (format!("regex_capture({t}, {p})"), format!("backtrack_capture({t}, {p})")),
                (format!("matches({t}, {p})"), format!("backtrack_matches({t}, {p})")),
                (format!("regex_replace({t}, {p}, \"<\\\\0>\")"), format!("backtrack_replace({t}, {p}, \"<\\\\0>\")")),
                (format!("regex_replace({t}, {p}, \"\\\\1$\\\\2\")"), format!("backtrack_replace({t}, {p}, \"\\\\1$\\\\2\")")),
            ] {
                src.push_str(&format!("when {a} != {b}\n    set distintos to append(distintos, {})\n", lit(&a)));
            }
        }
    }
    src.push_str("print(length(distintos), distintos)");
    eq(&src, "0 []");
}

#[test]
pub fn an_exponential_pattern_is_a_catchable_error() {
    // B15: el tope por defecto, en las cuatro
    let text = lit(&format!("{}b", "a".repeat(28)));
    let slow = lit(r"(a+)+$(?<!x)");
    err_has(&format!("print(backtrack_find_all({text}, {slow}))"), &format!("backtrack_find_all: {}", STEP_LIMIT));
    err_has(&format!("print(backtrack_matches({text}, {slow}))"), &format!("backtrack_matches: {}", STEP_LIMIT));
    err_has(&format!("print(backtrack_capture({text}, {slow}))"), &format!("backtrack_capture: {}", STEP_LIMIT));
    err_has(&format!("print(backtrack_replace({text}, {slow}, \"x\"))"), &format!("backtrack_replace: {}", STEP_LIMIT));
    // atrapable, y el programa sigue
    eq(
        &format!(
            "try\n    print(backtrack_find_all({text}, {slow}))\nrecover e\n    print(\"cortado\", contains(text(e), \"step limit exceeded\"))\nprint(backtrack_find_all(\"ab\", \"a(?=b)\"))"
        ),
        "cortado true\n[\"a\"]",
    );
    // B16: con el look-around adelante la crate lo delega entero al motor lineal
    eq(&format!("print(backtrack_find_all({text}, \"(?!x)(a+)+$\"))"), "[]");
    // el mensaje no lleva el texto buscado
    let got = out(&format!("print(backtrack_find_all({text}, {slow}))"));
    assert!(!got.contains("aaaa"), "{}", got);
}

/// B17: el tope es de la llamada. Con el de la crate (por búsqueda) estos 100 tramos se
/// encuentran todos: cada uno queda por debajo del millón.
#[test]
pub fn the_limit_belongs_to_the_call_not_to_each_search() {
    let pattern = lit(r"(?:a|aa)+(?<!x)c|a+b");
    let block = format!("{}b ", "a".repeat(21));
    eq(&format!("print(backtrack_find_all({}, {pattern}) == [{}])", lit(&block), lit(block.trim_end())), "true");
    // un tramo gasta 399 603 pasos: dos entran en el tope por defecto (1 048 576) y tres no
    eq(&format!("print(length(backtrack_find_all({}, {pattern})))", lit(&block.repeat(2))), "2");
    err_has(
        &format!("print(length(backtrack_find_all({}, {pattern})))", lit(&block.repeat(3))),
        &format!("backtrack_find_all: {}", STEP_LIMIT),
    );
    let many = lit(&block.repeat(100));
    err_has(&format!("print(length(backtrack_find_all({many}, {pattern})))"), &format!("backtrack_find_all: {}", STEP_LIMIT));
    err_has(&format!("print(backtrack_replace({many}, {pattern}, \"-\"))"), &format!("backtrack_replace: {}", STEP_LIMIT));
    // con un tope más alto, la misma llamada termina
    eq(&format!("print(length(backtrack_find_all({many}, {pattern}, max_steps = 200000000)))"), "100");
}

#[test]
pub fn max_steps_is_a_named_argument_with_a_range() {
    // B19: una búsqueda larga y legítima con un tope chico
    let text = lit(&format!("{}xy", "a".repeat(20_000)));
    eq(&format!("print(backtrack_find_all({text}, \"(?=x)x\"))"), "[\"x\"]");
    err_has(
        &format!("print(backtrack_find_all({text}, \"(?=x)x\", max_steps = 1000))"),
        "backtrack_find_all: step limit exceeded (max_steps = 1000) — the pattern did more work on this text than the limit allows; ",
    );
    // el tope es exacto: esta llamada gasta 121 269 pasos (seis por cada letra donde no arranca,
    // y uno cada 16 por el lugar que la VM mira entre los guardados al entrar al look-ahead)
    eq(&format!("print(backtrack_find_all({text}, \"(?=x)x\", max_steps = 121269))"), "[\"x\"]");
    err_has(
        &format!("print(backtrack_find_all({text}, \"(?=x)x\", max_steps = 121268))"),
        "backtrack_find_all: step limit exceeded (max_steps = 121268)",
    );
    // lo que el motor lineal resuelve entero no gasta pasos: anda con max_steps = 1
    eq(r#"print(backtrack_find_all("a b", "\\w(?=\\s|$)", max_steps = 1), backtrack_replace("ab", "a(?=b)", "-", max_steps = 1))"#, r#"["a", "b"] -b"#);
    // y lo que pasa por la VM gasta, por chico que sea
    err_has(
        r#"print(backtrack_matches("abab", "(ab)\\1", max_steps = 1))"#,
        "backtrack_matches: step limit exceeded (max_steps = 1) — ",
    );
    eq(r#"print(backtrack_matches("abab", "(ab)\\1", max_steps = 100), backtrack_capture("ab", "a(?=b)", max_steps = 536870913))"#, r#"true ["a"]"#);
    // sin techo: un entero que no entra en 64 bits vale como el mayor que entra
    eq(r#"print(backtrack_find_all("aab", "a(?!a)", max_steps = 100000000000000000000000000000))"#, r#"["a"]"#);
    // B21
    for bad in ["0", "-1", "-100000000000000000000000000000", "1.5", "\"x\"", "nothing", "true", "[5]"] {
        for call in [
            format!("backtrack_find_all(\"a\", \"a\", max_steps = {bad})"),
            format!("backtrack_matches(\"a\", \"a\", max_steps = {bad})"),
            format!("backtrack_capture(\"a\", \"a\", max_steps = {bad})"),
            format!("backtrack_replace(\"a\", \"a\", \"b\", max_steps = {bad})"),
        ] {
            err_has(&format!("print({call})"), "max_steps must be an integer of 1 or more, got ");
        }
    }
    err_has(
        r#"print(backtrack_find_all("a", "a", max_steps = 0))"#,
        "backtrack_find_all: max_steps must be an integer of 1 or more, got 0",
    );
    // sólo por nombre, y sólo ese nombre
    err_has(r#"print(backtrack_find_all("a", "a", 5))"#, "backtrack_find_all() takes at most 2 arguments, got 3");
    err_has(
        r#"print(backtrack_find_all("a", "a", limit = 5))"#,
        "backtrack_find_all() has no argument named 'limit' (named arguments it takes: max_steps)",
    );
    // las regex_* no lo tienen: no retroceden
    err_has(r#"print(regex_find_all("a", "a", max_steps = 5))"#, "regex_find_all() does not accept named arguments");
}

#[test]
pub fn invalid_patterns_and_arguments_are_errors() {
    // B22
    err_has(
        r#"print(backtrack_find_all("a", "("))"#,
        "invalid regex pattern '(': Parsing error at position 1: Opening parenthesis without closing parenthesis",
    );
    err_has(r#"print(backtrack_matches("a", "("))"#, "invalid regex pattern '(': Parsing error at position 1:");
    err_has(r#"print(backtrack_capture("", "(a)\\2"))"#, r"invalid regex pattern '(a)\\2': Error compiling regex: Invalid back reference to group 2");
    err_has(r#"print(backtrack_replace("", "(?<=a", "x"))"#, "invalid regex pattern '(?<=a': ");
    // un patrón desbalanceado no pasa por quedar bien envuelto; `matches` tampoco lo deja pasar
    // ya (hasta v0.6.59 daba `true`)
    err_has(r#"print(backtrack_matches("ab", "a)(b"))"#, "invalid regex pattern 'a)(b': ");
    err_has(r#"print(matches("ab", "a)(b"))"#, "invalid regex pattern 'a)(b': regex parse error:");
    let got = out(r#"print(matches("a", "("))"#);
    assert!(got.contains("invalid regex pattern '(': regex parse error:") && !got.contains("^(?:"), "{}", got);
    // B23: anidado o enorme, un error y no una caída
    let deep = lit(&format!("(?=x){}a{}", "(".repeat(500), ")".repeat(500)));
    err_has(&format!("print(backtrack_find_all(\"a\", {deep}))"), "Pattern too deeply nested");
    err_has(r#"print(backtrack_find_all("a", "(?=x)\\w{1000}"))"#, TOO_LARGE);
    // Ronda 1, N-3: un conteo que no entra en 32 bits es un error (era un `{` literal, y desde
    // dónde dependía de la plataforma); los conteos de siempre no cambian
    err_has(
        r#"print(backtrack_find_all("a", "a{4294967296}"))"#,
        "invalid regex pattern 'a{4294967296}': Parsing error at position 2: Repetition count is too large (the largest is 4294967295)",
    );
    err_has(r#"print(backtrack_matches("a", "(?=a)a{99999999999999999999999}"))"#, "Repetition count is too large");
    err_has(r#"print(regex_find_all("a", "a{4294967296}"))"#, "invalid regex pattern 'a{4294967296}': ");
    eq(r#"print(backtrack_find_all("aaa", "(?=a)a{3}"), backtrack_find_all("a{x}", "(?=a)a{x}"), regex_find_all("aaa", "a{3}"))"#, r#"["aaa"] ["a{x}"] ["aaa"]"#);
    // B24
    for call in [
        r#"backtrack_find_all("ab", "\\G")"#,
        r#"backtrack_matches("a", "\\Ga")"#,
        r#"backtrack_capture("a", "(?:\\G|x)a")"#,
        r#"backtrack_replace("a", "a\\G", "b")"#,
    ] {
        err_has(&format!("print({call})"), r"\G (continue from the previous match) is not supported by backtrack_*");
    }
    // B25: sólo texto (las regex_* convierten; estas no)
    err_has(
        r#"print(backtrack_find_all(bytes("a1"), "[0-9]"))"#,
        "backtrack_find_all: the text must be text, got bytes — decode it first with decode(b)",
    );
    err_has(r#"print(backtrack_find_all(5, "5"))"#, "backtrack_find_all: the text must be text, got number");
    err_has(r#"print(backtrack_matches("5", 5))"#, "backtrack_matches: the pattern must be text, got number");
    err_has(r#"print(backtrack_capture(nothing, "a"))"#, "backtrack_capture: the text must be text, got nothing");
    err_has(r#"print(backtrack_replace("a", "a", 5))"#, "backtrack_replace: the replacement must be text, got number");
    err_has(r#"print(backtrack_replace("a", ["a"], "b"))"#, "backtrack_replace: the pattern must be text, got list");
    err_has(r#"print(backtrack_find_all("a"))"#, "backtrack_find_all() needs 2 arguments, got 1");
}

/// B20: la pila de retroceso de la VM es fija; el error dice cómo salir, y con posesivos anda.
#[test]
pub fn a_very_long_run_fills_the_vm_stack_unless_the_repetition_is_possessive() {
    let spaces = "let espacios be join(apply(range(0, 30000), (i) => \"                                                  \"), \"\")\n";
    eq(
        &format!("{spaces}print(length(espacios), length(backtrack_find_all(espacios, \"\\\\s++(?!\\\\S)|\\\\s\")))"),
        "1500000 1",
    );
    let got = out(&format!("{spaces}print(length(backtrack_find_all(espacios, \"\\\\s+(?!\\\\S)|\\\\s+\")))"));
    assert!(
        got.starts_with("ERR: ")
            && got.contains(
                "backtrack_find_all: more than 1000000 pending backtrack points — a repetition that is not possessive \
                 ran over a long stretch of text, or look-behinds inside repetitions left their alternatives pending; \
                 make repetitions possessive (a++, a*+) or atomic ((?>…))"
            ),
        "{}",
        got
    );
    // atrapable, como el tope de pasos
    eq(
        &format!(
            "{spaces}try\n    print(backtrack_matches(espacios, \"\\\\s+(?!\\\\S)\"))\nrecover e\n    print(contains(text(e), \"pending backtrack points\"))"
        ),
        "true",
    );
}

/// Ronda 1, A-1: el tope cuenta trabajo, no retrocesos. Con look-arounds adentro de repeticiones
/// posesivas hay pocos retrocesos (3 202 en el primer caso) y mucho trabajo entre uno y otro: con
/// el tope de la crate estas llamadas tardaban 9 s y 7 s sin dar error.
#[test]
pub fn nested_look_arounds_in_repetitions_are_a_catchable_error() {
    let l2a = lit("(?:(?=(?:(?=[^x]*y)a)*+y)a)*+y");
    let l3a = lit("(?:(?=(?:(?=(?:(?=[^x]*y)a)*+y)a)*+y)a)*+y");
    let l2 = lit("(?:(?=(?:(?=[^x]*y)a)*y)a)*y");
    // sin tramos de texto: lo único que hay entre un retroceso y otro son instrucciones
    let l3b = lit("(?:(?=(?:(?=(?:(?=a)a)*+y)a)*+y)a)*+y");
    let letters = |n: usize| lit(&format!("{}y", "a".repeat(n)));
    err_has(
        &format!("print(length(backtrack_find_all({}, {l3b})))", letters(800)),
        &format!("backtrack_find_all: {}", STEP_LIMIT),
    );
    err_has(
        &format!("print(length(backtrack_find_all({}, {l2a})))", letters(3200)),
        &format!("backtrack_find_all: {}", STEP_LIMIT),
    );
    err_has(&format!("print(backtrack_matches({}, {l3a}))", letters(400)), &format!("backtrack_matches: {}", STEP_LIMIT));
    err_has(&format!("print(backtrack_capture({}, {l3a}))", letters(400)), &format!("backtrack_capture: {}", STEP_LIMIT));
    err_has(&format!("print(backtrack_replace({}, {l2a}, \"-\"))", letters(3200)), &format!("backtrack_replace: {}", STEP_LIMIT));
    // sobre un texto corto terminan
    eq(&format!("print(length(backtrack_find_all({t}, {l2a})), backtrack_matches({t}, {l2a}))", t = letters(100)), "1 true");
    // muchas búsquedas caras con max_steps = 1: la primera ya no entra (antes, cada una tenía un
    // primer escalón sin descontar, y 100 tramos tardaban 0,9 s sin error)
    let blocks = lit(&format!("{}y ", "a".repeat(100)).repeat(25));
    err_has(
        &format!("print(length(backtrack_find_all({blocks}, {l2a}, max_steps = 1)))"),
        "backtrack_find_all: step limit exceeded (max_steps = 1) — ",
    );
    // B-3: con la 0.18.0, sin posesivos, los look-aheads dejaban sus alternativas pendientes y
    // llenaban la pila de la VM con un texto corto. Desde la 0.20 un look-ahead es atómico: con
    // el tope por defecto corta el de pasos, y subiéndolo termina.
    err_has(&format!("print(backtrack_find_all({}, {l2}))", letters(1600)), &format!("backtrack_find_all: {}", STEP_LIMIT));
    eq(&format!("print(length(backtrack_find_all({}, {l2}, max_steps = 100000000)))", letters(1600)), "1");
    // Un look-behind no es atómico: adentro de una repetición deja una alternativa pendiente por
    // vuelta, además de la de la repetición, y 600 000 vueltas llenan la pila. Con el grupo
    // atómico adentro, no.
    let behind = lit("(?:(?<=(?:(?=a)a|(?=a)a))a)*y");
    let atomic = lit("(?:(?<=(?>(?=a)a|(?=a)a))a)*y");
    let long = "let largo be join(apply(range(0, 12000), (i) => \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"), \"\") + \"y\"\n";
    err_has(
        &format!("{long}print(backtrack_find_all(largo, {behind}, max_steps = 100000000))"),
        "backtrack_find_all: more than 1000000 pending backtrack points — a repetition that is not possessive ran over a \
         long stretch of text, or look-behinds inside repetitions left their alternatives pending",
    );
    eq(&format!("{long}print(length(backtrack_find_all(largo, {atomic}, max_steps = 100000000)))"), "1");
}

/// Ronda 2, A-2: un patrón que compila a demasiado es un error que el programa atrapa. Estos
/// pedían 649 MB el primero, y los otros toda la memoria que hubiera (el proceso abortaba);
/// `max_steps` no los frena, porque corre al buscar.
#[test]
pub fn a_pattern_that_compiles_to_too_much_is_a_catchable_error() {
    let wanted = |pattern: &str| format!("invalid regex pattern '{}': {}", pattern.replace('\\', "\\\\"), TOO_LARGE);
    for pattern in [r"(a|b\g<1>\g<1>)", r"(a|b\g<1>\g<1>\g<1>)", r"(a)(\g<1>\g<1>\g<1>)(\g<2>\g<2>\g<2>)(\g<3>\g<3>\g<3>)(\g<4>\g<4>\g<4>)(\g<5>\g<5>\g<5>)(\g<6>\g<6>\g<6>)(\g<7>\g<7>\g<7>)(\g<8>\g<8>\g<8>)(\g<9>\g<9>\g<9>)(\g<10>\g<10>\g<10>)(\g<11>\g<11>\g<11>)(\g<12>\g<12>\g<12>)"] {
        let p = lit(pattern);
        for call in [
            format!("backtrack_find_all(\"a\", {p})"),
            format!("backtrack_find_all(\"a\", {p}, max_steps = 1)"),
            format!("backtrack_capture(\"a\", {p})"),
            format!("backtrack_replace(\"a\", {p}, \"-\")"),
            format!("backtrack_matches(\"a\", {p})"),
        ] {
            eq(&format!("try\n    print({call})\nrecover e\n    print(e)\nprint(\"sigue\")"), &format!("{}\nsigue", wanted(pattern)));
        }
    }
    // una subrutina que no crece anda: una llamada, la recursión de un solo camino, los
    // paréntesis balanceados
    eq(
        r#"print(backtrack_find_all("aa", "(?=a)(a)\\g<1>"))
print(backtrack_find_all("bba", "(a|b\\g<1>)"))
print(backtrack_find_all("x ((a)(b)) y", "\\((?:[^()]|\\g<0>)*\\)"))
print(backtrack_matches("((a)(b))", "\\((?:[^()]|\\g<0>)*\\)"))"#,
        "[\"aa\"]\n[\"bba\"]\n[\"((a)(b))\"]\ntrue",
    );
}

/// Ronda 2: `backtrack_matches` no envuelve el texto del patrón (lo hace el motor sobre su
/// árbol), así que `\g<0>`, el patrón entero, sigue siendo lo que el programa escribió. Envuelto
/// como `^(?:…)$` las anclas entraban en la llamada y la respuesta era `false`, sin error.
#[test]
pub fn backtrack_matches_keeps_what_the_whole_pattern_call_means() {
    eq(
        r#"let balanceado be "\\((?:[^()]|\\g<0>)*\\)"
print(backtrack_matches("((a)(b))", balanceado), backtrack_matches("(a(b)", balanceado), backtrack_matches("(a)(b)", balanceado))
print(backtrack_find_all("x ((a)(b)) y (c", balanceado))
print(backtrack_matches("ab", "(?=a)(?:a|ab)"), backtrack_matches("ab", "a(?=b)"), backtrack_matches("a\n", "(?=a)a"))
print(backtrack_matches("a", "(?x)(?=a)a # una a"), backtrack_matches("abab", "(ab)\\1"))
print(backtrack_matches("((a)(b))", "^(?:" + balanceado + ")$"))
print(backtrack_find_all("xa", "a(?=$)"), backtrack_matches("xa", "a(?=$)"), backtrack_find_all("xa", "a(?=$)"))"#,
        "true false false\n[\"((a)(b))\"]\ntrue false false\ntrue true\nfalse\n[\"a\"] false [\"a\"]",
    );
}

/// Ronda 2, B-2: el tope por defecto crece con el patrón: `(64 + instrucciones) × bytes`. Un lexer
/// de 21 ramas con look-arounds en cada una es lineal y gasta 89 pasos por byte: con 64 por byte
/// era un error desde 12 KB.
#[test]
pub fn the_default_limit_fits_a_lexer_with_many_branches() {
    let prog = r#"let palabras be ["if", "else", "while", "for", "return", "break", "continue", "def", "class", "import", "from", "as", "with", "try", "except", "raise", "yield", "lambda", "pass", "not"]
let lexer be "(?<![\\w.])\\d+(?:\\.\\d+)?(?![\\w.])" + join(apply(palabras, (w) => "|(?<!\\w)" + w + "(?!\\w)"), "")
let linea be "El perro come 42 veces; if x == 10 else y = 20; while (a < b) return c.d(e) 3.14\n"
let t be join(apply(range(0, 250), (i) => linea), "")
print(length(t), length(backtrack_find_all(t, lexer)))
print(length(backtrack_replace(t, lexer, "")) < length(t))
print(backtrack_capture(t, lexer))
try
    print(length(backtrack_find_all(t, lexer, max_steps = 64 * length(t))))
recover e
    print(starts_with(text(e), "backtrack_find_all: step limit exceeded (max_steps = 1296000) — the pattern did more work on this text than the limit allows; "))"#;
    eq(prog, "20250 2000\ntrue\n[\"42\"]\ntrue");
}

/// Ronda 2, B-1: lo que una instrucción lee del texto se cobra. Un look-behind de largo fijo
/// enorme caminaba hasta el principio en cada posición, `\Z` leía los saltos de línea que
/// quedaban, y cada búsqueda armaba los lugares de sus grupos: tiempo cuadrático con 5 a 8 pasos
/// por byte. Ahora gastan pasos y el tope por defecto corta.
#[test]
pub fn what_an_instruction_reads_costs_steps() {
    let step_limit = |name: &str| format!("{}: step limit exceeded (max_steps = ", name);
    // 8 000 letras: el look-behind camina hasta el principio desde cada una
    err_has(
        &format!(
            "print(length(backtrack_find_all({}, {})))",
            lit(&format!("{}y", "a".repeat(8_000))),
            lit("(?:(?<=(?:(?=b)[ab]){999999999})c|a)*+y")
        ),
        &step_limit("backtrack_find_all"),
    );
    // 16 000 saltos de línea: `\Z` los lee todos desde cada uno
    err_has(
        &format!("print(length(backtrack_find_all({}, {})))", lit(&format!("{}y", "\n".repeat(16_000))).replace('\n', "\\n"), lit(r"(?:\Z(?=y)|\n)*+y")),
        &step_limit("backtrack_find_all"),
    );
    // 500 grupos que no participan, una búsqueda por letra
    let groups = lit(&format!("(?=a)(?:x{})?", "()".repeat(500)));
    err_has(&format!("print(length(backtrack_find_all({}, {groups})))", lit(&"a".repeat(20_000))), &step_limit("backtrack_find_all"));
    // lo mismo en chico termina, y da lo de siempre
    eq(
        r#"print(backtrack_find_all("ab", "(?<=a)b"), backtrack_find_all("a\n\n", "a(?=\\Z)"), backtrack_find_all("a\n\nb", "a(?=\\Z)"))
print(backtrack_capture("ab", "(a)(x)?(b)"))"#,
        "[\"b\"] [\"a\"] []\n[\"a\", nothing, \"b\"]",
    );
}

/// Ronda 2, N-1: una llave sin cerrar con un número que no entra en 32 bits es el texto que era;
/// con la llave que cierra, el conteo es un error.
#[test]
pub fn an_unclosed_brace_with_a_large_number_is_text() {
    eq(
        r#"print(backtrack_find_all("a{4294967296", "a{4294967296"))
print(backtrack_find_all("a{4294967296", "(?=a)a{4294967296"))
print(backtrack_find_all("a{1,4294967296", "(?=a)a{1,4294967296"))
print(backtrack_matches("a{4294967296", "a{4294967296"))
try
    print(backtrack_find_all("a", "a{4294967296}"))
recover e
    print(e)"#,
        "[\"a{4294967296\"]\n[\"a{4294967296\"]\n[\"a{1,4294967296\"]\ntrue\n\
         invalid regex pattern 'a{4294967296}': Parsing error at position 2: Repetition count is too large (the largest is 4294967295)",
    );
}

/// Ronda 1, B-1: un patrón envuelto escrito a mano no le saltea la validación a `matches` ni a
/// `backtrack_matches` (el compilado de uno era el que el otro iba a buscar a la caché).
#[test]
pub fn a_wrapped_pattern_written_by_hand_does_not_change_what_matches_answers() {
    eq(
        r#"print(regex_find_all("ab", "^(?:a)(b)$"))
try
    print(matches("ab", "a)(b"))
recover e
    print("error", contains(text(e), "invalid regex pattern 'a)(b': regex parse error:"), contains(text(e), "unopened group"))
print(backtrack_find_all("ab", "^(?:a)(b)$"))
try
    print(backtrack_matches("ab", "a)(b"))
recover e
    print("error", contains(text(e), "invalid regex pattern 'a)(b': Parsing error"))
print(matches("ab", "^(?:a)(b)$"), backtrack_matches("ab", "^(?:a)(b)$"), matches("xab", "^(?:a)(b)$"))"#,
        "[\"ab\"]\nerror true true\n[\"ab\"]\nerror true\ntrue true false",
    );
}

/// Ronda 2, B-3: `recover` liga el mensaje entero, siempre. La ubicación de un error va en su
/// campo y nunca escrita adelante del mensaje, así que no hay nada que recortar: un mensaje que
/// cita un valor del programa con forma de `hora:minuto:segundo: ` (o de `archivo:línea:columna: `)
/// llega como es. Con el recorte de la ronda 1 (prefijo terminado en `:dígitos:dígitos`), los dos
/// primeros perdían el principio, igual que en v0.6.59.
#[test]
pub fn recover_binds_the_whole_message_whatever_it_quotes() {
    eq(
        r#"try
    print(regex_find_all("a", "12:30:05: ("))
recover e
    print(starts_with(text(e), "invalid regex pattern '12:30:05: (': regex parse error:"))
try
    print(backtrack_find_all("a", "12:30:05: ((?=a)"))
recover e
    print(starts_with(text(e), "invalid regex pattern '12:30:05: ((?=a)': Parsing error at position "))
try
    print(int("1:2:3: x"))
recover e
    print(starts_with(text(e), "Cannot convert \"1:2:3: x\" to an integer: expected digits"))
try
    print(float("1:2:3: x"))
recover e
    print(e)
try
    print({"a": 1}["12:30:05: k"])
recover e
    print(e)
try
    raise("mod.syn:3:5: parece una ubicación")
recover e
    print(e)
task lanzar(m)
    raise(m)
try
    lanzar("12:30:05: en una task")
recover e
    print(e)
try
    try
        lanzar("x.syn:1:2: adentro")
    recover e
        raise(e)
recover e
    print(e)"#,
        "true\ntrue\ntrue\nCannot convert 1:2:3: x to float\nMap has no key '12:30:05: k'\n\
         mod.syn:3:5: parece una ubicación\n12:30:05: en una task\nx.syn:1:2: adentro",
    );
}

/// Ronda 2, B-3: el error de sintaxis de un módulo lleva la ubicación en su campo. `recover` liga
/// el mensaje solo, como siempre; el host ve `archivo:línea:columna: mensaje`, como siempre.
#[test]
pub fn a_module_with_a_syntax_error_keeps_its_location_out_of_the_message() {
    let broken = "export task f()\n    give (1 +\n";
    let caught = run_files(
        &[("malo.syn", broken)],
        "task cargar()\n    use \"./malo.syn\" as m\n    give m.f()\ntry\n    cargar()\nrecover e\n    print(\"recover:\", e)\n",
    );
    assert!(caught.success, "{:?}", caught.errors);
    assert_eq!(caught.output.len(), 1, "{:?}", caught.output);
    let bound = caught.output[0].strip_prefix("recover: ").expect("lo que ligó recover").to_string();
    assert!(bound.starts_with("Unexpected token"), "{}", bound);
    assert!(!bound.contains("malo.syn"), "{}", bound);
    // sin atrapar, el host ve la ubicación del módulo adelante del mismo mensaje
    let loose = run_files(&[("malo.syn", broken)], "use \"./malo.syn\" as m\nprint(m.f())\n");
    assert!(!loose.success);
    let shown = loose.errors.join("\n");
    assert!(shown.starts_with("Runtime error: ") && shown.ends_with(&format!(":3:1: {}", bound)), "{}", shown);
    assert!(shown.contains("malo.syn:3:1: "), "{}", shown);
}

/// El error de un patrón inválido llega entero al `recover`. Hasta v0.6.59 el `recover` tomaba por
/// ubicación (`archivo:línea:columna: `) cualquier comienzo con dos `:`, y a un patrón con dos
/// `(?:` le cortaba el `invalid regex pattern '…': ` de adelante. Un `raise` y el error de una
/// task siguen llegando sin su ubicación.
#[test]
pub fn recover_gets_the_whole_message_of_a_pattern_with_colons() {
    eq(
        r#"try
    print(regex_find_all("a", "(?:a)(?:b"))
recover e
    print(starts_with(text(e), "invalid regex pattern '(?:a)(?:b': regex parse error:"))
try
    print(backtrack_find_all("a", "(?:a)(?:b(?=c)"))
recover e
    print(starts_with(text(e), "invalid regex pattern '(?:a)(?:b(?=c)': Parsing error at position "))
try
    print(backtrack_matches("a", "(?:a)(?:b"))
recover e
    print(starts_with(text(e), "invalid regex pattern '(?:a)(?:b': Parsing error at position "))
try
    raise("a:b:c: del programa")
recover e
    print(e)
try
    raise("host:8080:x: del programa")
recover e
    print(e)
task falla()
    raise("adentro de una task")
try
    falla()
recover e
    print(e)
try
    print([1, 2][7])
recover e
    print(starts_with(text(e), "Index 7"), contains(text(e), ".syn:"))"#,
        "true\ntrue\ntrue\na:b:c: del programa\nhost:8080:x: del programa\nadentro de una task\ntrue false",
    );
}

/// Ronda 1, B-2: un patrón verboso que termina en comentario anda en `matches` y en
/// `backtrack_matches` (el comentario se comía el cierre del envoltorio).
#[test]
pub fn a_verbose_pattern_that_ends_in_a_comment_matches_in_full() {
    eq(
        r#"print(matches("a", "(?x)a # c"), matches("b", "(?x)a # c"), backtrack_matches("a", "(?x)a # c"), backtrack_matches("b", "(?x)a # c"))"#,
        "true false true false",
    );
    eq(
        r#"print(matches("ab", "(?x) a b # dos"), matches("a b", "(?x) a b # dos"), backtrack_matches("ab", "(?x) a (?=b) b # dos"), backtrack_matches("abx", "(?x) a (?=b) b # dos"))"#,
        "true false true false",
    );
    // con el salto escrito por el programa da lo mismo, y fuera del modo verboso `#` es un carácter
    eq(
        r#"print(matches("a", "(?x)a # c\n"), backtrack_matches("a", "(?x)a # c\n"), matches("a#b", "a#b"), matches("a#b\n", "a#b"), backtrack_matches("a#b", "a#(?=b)b"), backtrack_matches("a#b\n", "a#(?=b)b"))"#,
        "true true true false true false",
    );
    // las demás siguen leyendo el mismo patrón igual
    eq(r#"print(regex_find_all("xax", "(?x)a # c"), backtrack_find_all("xax", "(?x)a(?=x) # c"))"#, r#"["a"] ["a"]"#);
    // un inválido con comentario: el error es el de lo que el programa escribió
    let got = out(r#"print(matches("a", "(?x)( # abre"))"#);
    assert!(got.contains("invalid regex pattern '(?x)( # abre': regex parse error:") && !got.contains("^(?:"), "{}", got);
    err_has(r#"print(backtrack_matches("a", "(?x)( # abre"))"#, "invalid regex pattern '(?x)( # abre': Parsing error at position ");
}

/// Ronda 1, M-2 y N-2: en `serve`, los patrones compilados son de una request. El worker reusa el
/// hilo, y las cachés son del hilo: sin vaciarlas, un patrón quedaba en el worker (11 MB uno de 8
/// bytes) y la request siguiente podía medir si la anterior lo había compilado.
#[test]
pub fn a_serve_request_does_not_leave_its_compiled_patterns_in_the_worker() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    let port = TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /re/:t"
        let a be regex_find_all(params.t, "[a-z]+")
        let b be backtrack_find_all(params.t, "[a-z](?![a-z])")
        give {{"n": length(a) + length(b), "m": matches(params.t, "[a-z0-9]+")}}
"#,
        p = port
    );
    std::thread::spawn(move || {
        let _ = synsema_runtime::serve::run_serve_program(&prog, "v0660_serve.syn", false);
    });
    let mut ready = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            std::thread::sleep(Duration::from_millis(150));
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo en :{}", port);

    const REQUESTS: u64 = 30;
    let before = synsema_core::pattern_cache::dropped_total();
    for i in 0..REQUESTS {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let req = format!("GET /re/ab{}cd HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", i);
        sock.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        let _ = sock.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("\"n\": 4") && resp.contains("\"m\": true"), "{}", resp);
    }
    // Cada request compiló tres patrones (uno por familia, y el de `matches`) y los soltó al
    // terminar. La cuenta es de todo el proceso: otros tests pueden sumarle, nunca restarle. Si
    // los compilados quedaran en el worker, este server no soltaría ninguno.
    // La última request puede no haber terminado su limpieza cuando llega la respuesta.
    let mut dropped = 0;
    for _ in 0..100 {
        dropped = synsema_core::pattern_cache::dropped_total() - before;
        if dropped >= 3 * REQUESTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(dropped >= 3 * REQUESTS, "se soltaron {} compilados en {} requests", dropped, REQUESTS);
}

// ---------- las regex_* de siempre ----------

/// B28: el error de lo que el motor lineal no tiene lleva al arreglo.
#[test]
pub fn the_regex_error_points_to_the_backtracking_family() {
    for call in [
        r#"regex_find_all("a b", "\\s+(?!\\S)")"#,
        r#"regex_capture("a", "(?<=x)a")"#,
        r#"regex_replace("aa", "(a)\\1", "b")"#,
        r#"matches("a", "(?=a)a")"#,
        r#"find_all("a", "(?!b)a")"#,
    ] {
        let got = out(&format!("print({call})"));
        let hint = format!("supported\n{}", LINEAR_HINT);
        assert!(got.starts_with("ERR: ") && got.contains("invalid regex pattern '") && got.contains(&hint), "{}\n→ {}", call, got);
    }
    // y lo que nombra anda
    eq(r#"print(backtrack_find_all("a b", "\\s+(?!\\S)|\\s"), backtrack_replace("aa", "(a)\\1", "b"))"#, r#"[" "] b"#);
    // los demás errores de patrón no cambian
    let got = out(r#"print(regex_find_all("a", "("))"#);
    assert!(
        got.contains("invalid regex pattern '(': regex parse error:") && got.contains("error: unclosed group") && !got.contains("backtrack_"),
        "{}",
        got
    );
}

/// B29–B32: guardan sus compilados y dan lo de v0.6.59, byte a byte (también lo que convierten:
/// `regex_find_all(bytes(…))` busca en `bytes(6131)`; eso no es de esta versión).
#[test]
pub fn the_linear_family_keeps_its_results() {
    eq(r#"print(regex_find_all("a   b", "\\s+"), regex_capture("x", "y"), regex_find_all(bytes("a1"), "[0-9]"), regex_find_all(5, "[0-9]"))"#, r#"["   "] nothing ["6", "1", "3", "1"] ["5"]"#);
    eq(r#"print(regex_capture("2026-09", "(\\d+)-(\\d+)(x)?"), regex_capture("hola mundo", "m\\w+"))"#, r#"["2026", "09", nothing] ["mundo"]"#);
    eq(r#"print(regex_replace("ab cd", "(\\w)(\\w)", "\\2\\1"), regex_replace("ab", "a", "$1"), regex_replace("ab", "a", "[\\3]"))"#, "ba dc $1b []b");
    eq(r#"print(regex_find_all("aaaa", "a++a"), regex_find_all("ab", "x*"), regex_find_all("a1 b2", "([a-z])([0-9])"))"#, r#"["aaaa"] ["", "", ""] ["a1", "b2"]"#);
    eq(r#"print(matches("abc", "a.c"), matches("abc", "b"), matches("a\n", "a"))"#, "true false false");
    // B30: la misma llamada muchas veces
    eq(
        r#"let n be 0
each i in range(0, 500)
    set n to n + length(regex_find_all("abc 123 def", "\\w+")) + length(backtrack_find_all("abc 123 def", "\\w+(?=\\s|$)"))
print(n)"#,
        "3000",
    );
    // `matches` después de `regex_find_all` con el mismo patrón: el compilado envuelto es otro
    eq(
        r#"print(regex_find_all("xa", "a"), matches("xa", "a"), regex_find_all("xa", "a"), matches("a", "a"))
print(backtrack_find_all("xa", "a(?=$)"), backtrack_matches("xa", "a(?=$)"), backtrack_matches("a", "a(?=$)"))"#,
        "[\"a\"] false [\"a\"] true\n[\"a\"] false true",
    );
    // B31: más patrones que lugares en la caché, en ronda
    eq(
        r#"let mal be 0
each vuelta in range(0, 2)
    each i in range(0, 40)
        let t be "n" + text(i) + "=" + text(i * 3 + vuelta) + " n" + text(i + 100) + "=7"
        when regex_find_all(t, "\\bn" + text(i) + "=\\d+") != ["n" + text(i) + "=" + text(i * 3 + vuelta)]
            set mal to mal + 1
        when backtrack_find_all(t, "(?<=\\bn" + text(i) + "=)\\d+") != [text(i * 3 + vuelta)]
            set mal to mal + 1
print(mal)"#,
        "0",
    );
    // B32: un patrón inválido da su error cada vez
    eq(
        r#"let errores be []
each i in range(0, 2)
    try
        print(regex_find_all("a", "("))
    recover e
        set errores to append(errores, text(e))
    try
        print(backtrack_find_all("a", "("))
    recover e
        set errores to append(errores, text(e))
print(errores[0] == errores[2], errores[1] == errores[3], contains(errores[0], "unclosed group"), contains(errores[1], "Opening parenthesis"))"#,
        "true true true true",
    );
}

// ---------- C: to_list(bytes) ----------

#[test]
pub fn to_list_of_bytes_gives_integers() {
    // C1–C4
    eq(r#"print(to_list(bytes("h\u00f1")), to_list(bytes("")), to_list(bytes([0, 255])))"#, "[104, 195, 177] [] [0, 255]");
    eq(
        r#"let b be bytes("el \u00f1and\u00fa")
let l be to_list(b)
print(bytes(l) == b, length(l) == length(b), is_integer(l[0]), type_of(l[0]), l[0] + 1)"#,
        "true true true number 102",
    );
    // lo que el tokenizador hacía con un bucle por índice
    eq(
        r#"let b be bytes("a\u00f1")
let ids be []
each i in range(0, length(b))
    set ids to append(ids, b[i])
print(ids == to_list(b))"#,
        "true",
    );
    // C5: con un array, lo de siempre
    eq("print(to_list(array([1, 2])), to_list(array([[1, 2], [3, 4]])))", "[1.0, 2.0] [[1.0, 2.0], [3.0, 4.0]]");
    // C6
    err_has("print(to_list([1, 2]))", "to_list expects an array or bytes, got list");
    err_has(r#"print(to_list("ab"))"#, "to_list expects an array or bytes, got text");
    err_has("print(to_list(nothing))", "to_list expects an array or bytes, got nothing");
}

// ---------- etiquetas (A16, B27, C7) ----------

/// Son cómputo puro: lo que sale lleva la etiqueta de lo que entró (el texto, el patrón o el
/// reemplazo).
#[test]
pub fn the_new_builtins_keep_the_label() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
    let p = "let p be private(\"e\\u0301 ab\", \"x\")\nlet q be private(\"a(?=b)\", \"x\")\nlet pb be private(bytes(\"h\"), \"x\")\n";
    for (expr, want) in [
        ("length(nfc(p))", "4"),
        ("length(nfd(p))", "5"),
        ("nfkc(p) == nfc(p)", "true"),
        ("nfkd(p) == nfd(p)", "true"),
        ("backtrack_find_all(p, \"a(?=b)\")", "[\"a\"]"),
        ("backtrack_find_all(\"ab\", q)", "[\"a\"]"),
        ("backtrack_matches(p, \"(?=e).*\")", "true"),
        ("backtrack_matches(\"a\", q)", "false"),
        ("backtrack_capture(p, \"(a)(?=b)\")", "[\"a\"]"),
        ("backtrack_capture(\"ab\", q)", "[\"a\"]"),
        ("backtrack_replace(\"ab\", q, \"-\")", "-b"),
        ("backtrack_replace(\"ab\", \"a(?=b)\", p) == p + \"b\"", "true"),
        ("backtrack_find_all(p, \"a(?=b)\", max_steps = 5)", "[\"a\"]"),
        ("to_list(pb)", "[104]"),
    ] {
        let src = format!("{}let r be {}\n", p, expr);
        let program = synsema_core::parser::parse_source(&src, "<v0660>").unwrap();
        let mut interp = Interpreter::new();
        synsema_stdlib::unicode_norm::register_unicode_norm_builtins(&interp);
        synsema_stdlib::backtrack::register_backtrack_builtins(&interp);
        interp.set_labels(true);
        interp.set_labels_detail_to_program(true);
        if let Err(Control::Error(e)) = interp.execute(&program) {
            panic!("{}: {}", expr, e);
        }
        let v = env_get(&interp.global_env, "r").expect("sin r");
        assert_eq!(
            (label_display_raw(&label_deep(&v)).as_str(), strip_deep(&v).to_string().as_str()),
            ("x", want),
            "{}",
            expr
        );
    }
}

/// Los ocho nombres nuevos están clasificados como cómputo puro (junto a `matches` y `regex_*`).
#[test]
pub fn the_new_names_are_pure_for_labels() {
    for name in ["nfc", "nfd", "nfkc", "nfkd", "backtrack_matches", "backtrack_find_all", "backtrack_capture", "backtrack_replace", "to_list"] {
        assert!(synsema_stdlib::label_lists::LABEL_PURE_BUILTINS.contains(&name), "{}", name);
        assert!(!synsema_stdlib::label_lists::LABEL_SINK_BUILTINS.contains(&name), "{}", name);
    }
}

// ---------- ronda 3 de la auditoría ----------

/// Una referencia escrita adentro de su grupo lee lo que el grupo coincidió la vez anterior, como
/// en PCRE (es lo que hace la crate desde la 0.20). Con `fancy-regex` 0.18.0 los dos primeros eran
/// un pánico de la VM, y en la ronda 3 todos eran un error del patrón.
#[test]
pub fn a_backreference_inside_its_group_reads_what_the_group_matched_the_time_before() {
    eq(
        r#"print(backtrack_find_all("xaxa", "(?:x(a\\1?))+"), backtrack_capture("xaxa", "(?:x(a\\1?))+"), backtrack_matches("xaxa", "(?:x(a\\1?)){2}"))"#,
        r#"["xaxa"] ["a"] true"#,
    );
    eq(
        r#"print(backtrack_find_all("aaa", "(a\\1?)+"), backtrack_capture("aaa", "(a\\1?)+"), backtrack_replace("aaa-", "(?<n>a\\k<n>?)+", "<\\1>"))"#,
        r#"["aaa"] ["aa"] <aa>-"#,
    );
    eq(r#"print(backtrack_capture("xaxaa", "(?:x(\\1?a))+"), backtrack_capture("aaaa", "(a\\1?)+"))"#, r#"["aa"] ["a"]"#);
    // la primera vez no hay nada que leer: no coincide
    eq(
        r#"print(backtrack_find_all("aa", "(a\\1)"), backtrack_capture("aa", "(a\\1)"), backtrack_matches("aa", "(a\\1)"))"#,
        "[] nothing false",
    );
    // después de que el grupo cierra, la referencia de siempre
    eq(r#"print(backtrack_find_all("xaxa abab", "(?:x(a)\\1?)+|(ab)\\2"))"#, r#"["xaxa", "abab"]"#);
    // Ronda 4, M-1: `(?(1)…)` adentro del grupo 1 pregunta si el grupo coincidió, no si empezó
    // (la 0.18.0 daba `xab` y sin coincidencia en la primera línea, y sin coincidencia y `ab` en
    // la segunda)
    eq(
        r#"print(backtrack_find_all("xacxab", "(?:x(a(?(1)b|c)))+"), backtrack_find_all("xac", "(?:x(a(?(1)b|c)))+"))"#,
        r#"["xacxab"] ["xac"]"#,
    );
    eq(
        r#"print(backtrack_find_all("ac", "(a(?(1)b|c))+"), backtrack_find_all("acab", "(a(?(1)b|c))+"), backtrack_capture("acab", "(a(?(1)b|c))+"))"#,
        r#"["ac"] ["acab"] ["ab"]"#,
    );
    // Ronda 4, B-1: por una llamada de subrutina la referencia lee lo mismo, lo de la vez
    // anterior (la 0.18.0 leía el texto vacío y daba `abb`, `abaa` y `["b", ""]`)
    let through_a_call = lit(r"(?:(a|b\g<2>))+(\1)");
    let anchored = lit(r"(?:(a|b\g<2>))+$(\1)?");
    eq(
        &format!(
            "print(backtrack_find_all(\"abb\", {through_a_call}), backtrack_find_all(\"abaa\", {through_a_call}), \
             backtrack_capture(\"ab\", {anchored}))"
        ),
        r#"[] ["aa"] nothing"#,
    );
    eq(
        r#"print(backtrack_find_all("xaxaa", "(?:x(a\\g<2>?))+(\\1)"), backtrack_capture("xaxaa", "(?:x(a\\g<2>?))+(\\1)"))"#,
        r#"["xaxaa"] ["a", "a"]"#,
    );
}

/// Ronda 4, A-3 y M-2: la referencia sin distinguir mayúsculas compara letra por letra.
#[test]
pub fn round4_a_case_insensitive_backreference_compares_letter_by_letter() {
    // M-2: dos letras que son la misma pueden ocupar distinta cantidad de bytes. La referencia
    // se comía lo que sobraba (las tres primeras terminaban en `!`, `x` y `€`) o no coincidía
    // (las tres siguientes). Las siete dan lo que dan Perl y el módulo `regex` de Python.
    for (pattern, text, found) in [
        ("(?i)(stra\u{1e9e}e)\\1", "STRA\u{1e9e}Estra\u{df}e!", "STRA\u{1e9e}Estra\u{df}e"),
        ("(?i)(\u{1e9e})\\1", "\u{1e9e}\u{df}x", "\u{1e9e}\u{df}"),
        ("(?i)(\u{212a}\u{17f})\\1", "\u{212a}\u{17f}ks\u{20ac}", "\u{212a}\u{17f}ks"),
        ("(?i)(\u{212a}\u{17f})\\1", "\u{212a}\u{17f}ksz", "\u{212a}\u{17f}ks"),
        ("(?i)(\u{17f})\\1", "\u{17f}s", "\u{17f}s"),
        ("(?i)(s)\\1", "s\u{17f}", "s\u{17f}"),
        ("(?i)(\u{e9})\\1", "\u{e9}\u{c9}", "\u{e9}\u{c9}"),
    ] {
        eq(
            &format!(
                "print(backtrack_find_all({t}, {p}) == [{f}], backtrack_matches({f}, {p}))",
                t = lit(text),
                p = lit(pattern),
                f = lit(found)
            ),
            "true true",
        );
    }
    // A-3: 70 000 `é` y 70 000 `É`, con el tope por defecto. Con la 0.18.0 el programa terminaba
    // («internal error in the engine … literal hir should get built successfully») sin pasar por
    // `recover`.
    let text = lit(&format!("{}{}", "\u{e9}".repeat(70_000), "\u{c9}".repeat(70_000)));
    let pattern = lit("(?i)^(\u{e9}+)\\1");
    eq(
        &format!("try\n    print(backtrack_matches({text}, {pattern}))\nrecover e\n    print(e)\nprint(\"sigue\")"),
        "true\nsigue",
    );
}

/// Ronda 4, A-1 y A-2: el techo del compilado cuenta lo que una búsqueda necesita. La tabla con
/// la que el motor lineal sigue los grupos (36 MB con 60 grupos sobre `\w`, 99 MB con 100) no la
/// contaba nadie: en `backtrack_*` hacía rehacer la caché en cada búsqueda (20 KB en 100 s) o
/// quedaba retenida. Ahora esos patrones son un error que el programa atrapa.
#[test]
pub fn round4_the_size_limit_counts_what_a_search_needs() {
    let wanted = |pattern: &str| format!("invalid regex pattern '{}': {}", pattern.replace('\\', "\\\\"), TOO_LARGE);
    let groups = format!(r"(?=\w)({})", r"(\w)".repeat(60));
    let row = format!("(?m)^(?=\\w){}", vec![r"(\w+)"; 60].join(","));
    let whole = r"(\w)".repeat(100);
    for pattern in [&groups, &row, &whole] {
        let p = lit(pattern);
        eq(
            &format!("try\n    print(backtrack_find_all(\"a\", {p}))\nrecover e\n    print(e)\nprint(\"sigue\")"),
            &format!("{}\nsigue", wanted(pattern)),
        );
    }
    // con 30 grupos entra, y busca: tres coincidencias de 30 letras en cada palabra de 100
    let groups = lit(&format!(r"(?=\w)({})", r"(\w)".repeat(30)));
    let text = lit(&format!("{} ", "a".repeat(100)).repeat(20));
    eq(&format!("print(length(backtrack_find_all({text}, {groups})))"), "60");
    // lo que pesa son los grupos sobre clases Unicode: la fila de 60 campos con una clase ASCII
    // entra, y sin grupos también
    let ascii_row = lit(&format!("(?m)^(?=[0-9]){}", vec!["([0-9]+)"; 60].join(",")));
    // (el salto de línea va con su escape: un literal de texto no puede tener uno adentro)
    let csv = format!("\"{}\"", format!("{}\\n", vec!["123"; 60].join(",")).repeat(3));
    eq(&format!("print(length(backtrack_find_all({csv}, {ascii_row})), length(backtrack_capture({csv}, {ascii_row})))"), "3 60");
    // las `regex_*` acotan el compilado, no esto: el mismo patrón de 60 grupos anda (y su caché
    // de búsqueda, que pasa de lo retenido, no sobrevive a la llamada)
    let linear = lit(&r"(\w)".repeat(60));
    eq(&format!("print(length(regex_find_all({text}, {linear})))"), "20");
}

/// Lo que encontró el fuzz propio: un grupo sale con el comienzo y el fin de la misma
/// coincidencia. Con upstream el primero era un pánico al leer el grupo, y los paréntesis
/// balanceados y la llamada repetida daban otro texto (`(b))` y `abb`).
#[test]
pub fn round3_a_group_called_as_a_subroutine_keeps_its_own_match() {
    eq(r#"print(backtrack_capture("b", "(?=b\\g<1>)((?=))"), backtrack_replace("b", "(?=b\\g<1>)((?=))", "[\\1]"))"#, r#"[""] []b"#);
    eq(r#"print(backtrack_capture("((a)(b))", "(\\((?:[^()]|\\g<1>)*\\))"))"#, r#"["((a)(b))"]"#);
    eq(r#"print(backtrack_replace("f((a)(b)) g(c)", "(\\((?:[^()]|\\g<1>)*\\))", "<\\1>"))"#, "f<((a)(b))> g<(c)>");
    eq(r#"print(backtrack_capture("aababb", "(a(?:\\g<1>)*b)"), backtrack_capture("aabb", "(a\\g<1>?b)"))"#, r#"["aababb"] ["aabb"]"#);
}

/// M-2: un patrón de más de 16 KiB es un error antes de parsearlo, con un mensaje que no lo
/// repite. M-1: el mensaje del tope dice la causa más común y su remedio.
#[test]
pub fn round3_the_pattern_has_a_maximum_length_and_the_step_limit_names_the_anchor() {
    let fits = format!("(?=a){}", "a".repeat(16 * 1024 - 5));
    eq(&format!("print(backtrack_find_all(\"a\", {}), backtrack_matches(\"a\", {}))", lit(&fits), lit(&fits)), "[] false");
    let long = lit(&format!("{}a", fits));
    for (name, call) in [
        ("backtrack_find_all", format!("backtrack_find_all(\"a\", {long})")),
        ("backtrack_matches", format!("backtrack_matches(\"a\", {long})")),
        ("backtrack_capture", format!("backtrack_capture(\"a\", {long}, max_steps = 7)")),
        ("backtrack_replace", format!("backtrack_replace(\"a\", {long}, \"b\")")),
    ] {
        let got = out(&format!("print({call})"));
        let want = format!(
            "{}: the pattern is 16385 bytes long, and a backtrack_* pattern may be at most 16384; split it into several patterns",
            name
        );
        assert!(got.starts_with("ERR: ") && got.ends_with(&want) && got.len() < 400, "{}", &got[..got.len().min(400)]);
    }
    // las `regex_*` no tienen ese máximo
    eq(&format!("print(length(regex_find_all(\"a\", {})))", lit(&"a".repeat(20_000))), "0");
    // M-1: 800 cifras y un punto con el tope por defecto
    let number = lit(&format!("x {}. fin", "1".repeat(800)));
    let got = out(&format!("print(backtrack_find_all({number}, \"\\\\d+(?![\\\\d.])\"))"));
    assert!(got.starts_with("ERR: ") && got.ends_with(&format!("backtrack_find_all: {}", STEP_LIMIT)), "{}", got);
    // con el comienzo dicho, una corrida de 16 000 entra
    let number = lit(&format!("x {}. 77 fin", "1".repeat(16_000)));
    eq(&format!("print(backtrack_find_all({number}, \"(?<!\\\\d)\\\\d+(?![\\\\d.])\"))"), r#"["77"]"#);
}

/// `\b` va al motor lineal (desde la 0.20 de la crate; en la ronda 3, B-1, corría en la VM y
/// gastaba pasos): un patrón que sólo tiene eso no gasta ninguno. N-1: caminar hacia atrás cobra
/// los bytes que camina, así que el mismo look-behind sobre letras de dos bytes gasta más.
#[test]
pub fn round3_word_boundaries_and_walking_back() {
    eq(r#"print(backtrack_find_all("a foo b food", "\\bfoo\\b", max_steps = 1))"#, r#"["foo"]"#);
    eq(r#"print(backtrack_find_all("a foo b bar", "\\b(?:foo|bar|baz)\\b", max_steps = 1))"#, r#"["foo", "bar"]"#);
    eq(r#"print(backtrack_find_all("a foo b bar", "(?:foo|bar|baz)", max_steps = 1))"#, r#"["foo", "bar"]"#);
    // al lado de un look-ahead corre en la VM, y da lo mismo
    eq(r#"print(backtrack_find_all("a foo b food", "(?=f)\\bfoo\\b"))"#, r#"["foo"]"#);
    err_has(
        r#"print(backtrack_find_all("a foo b food", "(?=f)\\bfoo\\b", max_steps = 1))"#,
        "backtrack_find_all: step limit exceeded (max_steps = 1) — ",
    );
    // 2 000 letras y una x: 106 014 pasos con letras de un byte, 200 387 con letras de dos
    let one = lit(&format!("{}x", "e".repeat(2000)));
    let two = lit(&format!("{}x", "\u{e9}".repeat(2000)));
    eq(&format!("print(backtrack_find_all({one}, \"(?<=a{{1000}})x\", max_steps = 106014))"), "[]");
    err_has(&format!("print(backtrack_find_all({one}, \"(?<=a{{1000}})x\", max_steps = 106013))"), "step limit exceeded (max_steps = 106013)");
    eq(&format!("print(backtrack_find_all({two}, \"(?<=a{{1000}})x\", max_steps = 200387))"), "[]");
    err_has(&format!("print(backtrack_find_all({two}, \"(?<=a{{1000}})x\", max_steps = 200386))"), "step limit exceeded (max_steps = 200386)");
}

/// Ronda 5, M-1: el grupo de una repetición sin tope que puede coincidir vacía se lee igual
/// corra donde corra el patrón, y es la lectura de Perl (la última vuelta, aunque sea la vacía).
/// Un look-ahead al final o un look-behind al lado no cambian lo que el patrón coincide, y
/// cambiaban el grupo: sin ellos la repetición iba al motor lineal, que se queda con la última
/// vuelta que leyó algo. Las `regex_*` son ese motor, y leen como antes.
#[test]
pub fn round5_the_groups_of_a_repetition_that_can_match_empty() {
    for pattern in ["(b?)*", "(b?)*(?=)", "(b?)*(?<!x)", "(?<!x)(b?)*", "(b?)*+"] {
        let p = lit(pattern);
        eq(
            &format!("print(backtrack_capture(\"b\", {p}), backtrack_replace(\"b\", {p}, \"<\\\\1>\"), backtrack_find_all(\"b\", {p}))"),
            r#"[""] <> ["b"]"#,
        );
    }
    eq(
        r#"print(backtrack_capture("ab,cd,", "(?:(\\w*),?)*"), backtrack_capture("ab,cd,", "(?:(\\w*),?)*(?<!x)"))"#,
        r#"[""] [""]"#,
    );
    eq(
        r#"print(backtrack_capture("ak", "b?((a|b){0,2})+"), backtrack_capture("ak", "b?((a|b){0,2})+(?=.a*)"))"#,
        r#"["", "a"] ["", "a"]"#,
    );
    // el otro motor, el de siempre
    eq(r#"print(regex_capture("b", "(b?)*"), regex_capture("ab,cd,", "(?:(\\w*),?)*"))"#, r#"["b"] ["cd"]"#);
    // esa repetición corre en el motor de retroceso y gasta pasos, tenga o no un grupo adentro
    // (ronda 6); una contada y lo que queda al sacar el look-ahead del final siguen yendo
    // enteras al lineal
    err_has(
        r#"print(backtrack_capture("b", "(b?)*", max_steps = 1))"#,
        "backtrack_capture: step limit exceeded (max_steps = 1) — ",
    );
    eq(
        r#"print(backtrack_capture("b", "(b?){0,3}", max_steps = 1), backtrack_find_all("b", "(?:b){0,3}", max_steps = 1))"#,
        r#"[""] ["b"]"#,
    );
    eq(r#"print(backtrack_find_all("clave: valor", "\\w+(?=:)", max_steps = 1))"#, r#"["clave"]"#);
    // un grupo adentro de `{0}` existe y no coincide; la crate `regex` lo borra (N-2)
    eq(r#"print(backtrack_capture("a", "a(b){0}"), regex_capture("a", "a(b){0}"))"#, r#"[nothing] ["a"]"#);
}

/// Ronda 5, B-1: el motor de `regex_*` pasó de `regex-automata` 0.4.14 a 0.4.18 (la pide el
/// motor de `backtrack_*`), que arregla regex#1354: una búsqueda que daba una coincidencia que no
/// era la de más a la izquierda. v0.6.59 imprime `["b", "b"] ["b"] za<$0><$0>` en la primera
/// línea. No hay mutación propia: es una dependencia, y esto avisa si su versión vuelve atrás.
#[test]
pub fn round5_regex_gives_the_leftmost_match() {
    eq(
        r#"print(regex_find_all("zabb", ".abb|b"), regex_capture("zabb", ".abb|b"), regex_replace("zabb", ".abb|b", "<$0>"))"#,
        r#"["zabb"] ["zabb"] <$0>"#,
    );
    eq(
        r#"print(regex_find_all(" zabb", "\\s+\\w+bb|b"), regex_find_all("xzbacbbac", "(?:..acbb|b)a(?:c|d)"))"#,
        r#"[" zabb"] ["zbacbbac"]"#,
    );
    eq(
        r#"print(regex_find_all("xaaabb", "(?:[a-wyz]{3}|[a-wyz]).b"), backtrack_find_all("zabb", ".abb|b"))"#,
        r#"["aaabb"] ["zabb"]"#,
    );
}

/// Ronda 5, B-3 y B-2: un cuantificador sobre otro y un nombre de grupo en dos grupos son
/// errores de patrón inválido, en las cuatro funciones, y `try` los atrapa. La crate leía la
/// llave contada como texto (`a{2}{3}` coincidía con `aa{3}`) y, de dos grupos con el mismo
/// nombre, `\k<n>` leía sólo el último.
#[test]
pub fn round5_a_quantifier_on_a_quantifier_and_a_name_on_two_groups_are_errors() {
    let stacked = "invalid regex pattern 'a{2}{3}': Parsing error at position 4: Target of repeat operator is invalid";
    let named = "invalid regex pattern '(?:(?<n>a)|(?<n>b))\\\\k<n>': the group name 'n' is on more than one group, and \
                 backtrack_* take one group per name (regex engines disagree on what \\k<n> reads otherwise); give each \
                 group its own name";
    for (pattern, text, want) in [("a{2}{3}", "aaaaaa", stacked), ("(?:(?<n>a)|(?<n>b))\\k<n>", "aa", named)] {
        let (p, t) = (lit(pattern), lit(text));
        for call in [
            format!("backtrack_find_all({t}, {p})"),
            format!("backtrack_capture({t}, {p})"),
            format!("backtrack_replace({t}, {p}, \"x\")"),
            format!("backtrack_matches({t}, {p})"),
            format!("backtrack_find_all(\"\", {p}, max_steps = 1)"),
        ] {
            let got = out(&format!("print({call})"));
            assert!(got.starts_with("ERR: ") && got.ends_with(want), "{}\n→ {}", call, got);
            eq(&format!("try\n    print({call})\nrecover e\n    print(\"atrapado\")"), "atrapado");
        }
    }
    // agrupada es la repetición de la repetición, y una llave que no es una cuenta sigue siendo texto
    eq(
        r#"print(backtrack_matches("aaaaaa", "(?:a{2}){3}"), backtrack_find_all("aa{x} aa{3", "a{2}\\{3|a{2}{x}"))"#,
        r#"true ["aa{x}", "aa{3"]"#,
    );
    eq(r#"print(backtrack_find_all("aa bb", "(?<n>a)\\k<n>|(?<m>b)\\k<m>"))"#, r#"["aa", "bb"]"#);
    // las `regex_*` leen la repetición de la repetición, como antes
    eq(r#"print(matches("aaaaaa", "a{2}{3}"))"#, "true");
}

/// Ronda 6, M-1: una repetición sin tope que puede coincidir vacía coincide igual corra donde
/// corra, también sin un grupo adentro. `(?:a?|b)+` sobre `ab` daba `["ab"]` suelto (el motor
/// lineal nunca sigue una vuelta vacía: descarta ese camino y toma el que lee) y `["a", ""]` con
/// un `(?<!x)` al lado (el motor de retroceso toma la vuelta vacía y sale, como Perl y PCRE).
/// Ahora corre siempre en el de retroceso. Las `regex_*` son el otro motor, y leen como antes.
#[test]
pub fn round6_a_repetition_that_can_match_empty_matches_the_same_wherever_it_runs() {
    for pattern in ["(?:a?|b)+", "(?:a?|b)+(?<!x)", "(?<!x)(?:a?|b)+", "(?:a?|b)+(?=)"] {
        let p = lit(pattern);
        eq(
            &format!("print(backtrack_find_all(\"ab\", {p}), backtrack_replace(\"ab\", {p}, \"-\"), backtrack_matches(\"ab\", {p}))"),
            r#"["a", ""] -b- true"#,
        );
    }
    eq(
        r#"print(backtrack_capture("ab", "((?:a?|b)*)"), backtrack_capture("ab", "((?:a?|b)*)(?<!x)"))"#,
        r#"["a"] ["a"]"#,
    );
    eq(
        r#"print(backtrack_find_all(" , ,", "(?:\\s*|,)*"), backtrack_find_all(" , ,", "(?:\\s*|,)*(?<!x)"))"#,
        r#"[" ", " ", ""] [" ", " ", ""]"#,
    );
    // el otro motor, el de siempre
    eq(r#"print(regex_find_all("ab", "(?:a?|b)+"))"#, r#"["ab"]"#);
    // gasta pasos también sin nada más de la familia, y es la forma que retrocede
    err_has(
        r#"print(backtrack_find_all("b", "(?:b?)*", max_steps = 1))"#,
        "backtrack_find_all: step limit exceeded (max_steps = 1) — ",
    );
    let got = out(&format!("print(backtrack_find_all({}, \"(?:a*)*b\"))", lit(&"a".repeat(30))));
    assert!(got.starts_with("ERR: ") && got.ends_with(&format!("backtrack_find_all: {}", STEP_LIMIT)), "{}", got);
    // una contada sigue yendo entera al motor lineal, aunque su cuerpo pruebe primero el vacío
    eq(r#"print(backtrack_find_all("ab", "(?:a?|b){0,3}", max_steps = 1))"#, r#"["a", ""]"#);
}

/// Ronda 6, propio: una alternancia cuyas ramas empiezan igual coincide igual corra donde corra.
/// El motor lineal saca factor común de ese comienzo (`a?a|a?b` pasa a ser `a?(?:a|b)`), y cuando
/// el comienzo puede coincidir de más de una manera prefiere otra rama: `a?a|a?b` sobre `ab`
/// daba `["ab"]` suelto y `["a", "b"]` con un `(?<!x)` al lado, que es lo que dan Perl y Python.
/// Ahora corre siempre en el motor de retroceso. Las `regex_*` son el otro motor, y leen como
/// antes.
#[test]
pub fn round6_an_alternation_with_a_common_beginning_matches_the_same_wherever_it_runs() {
    for pattern in ["a?a|a?b", "(?:a?a|a?b)(?<!x)", "(?<!x)(?:a?a|a?b)", "(?:a?a|a?b)(?=)"] {
        let p = lit(pattern);
        eq(
            &format!("print(backtrack_find_all(\"ab\", {p}), backtrack_replace(\"ab\", {p}, \"-\"))"),
            r#"["a", "b"] --"#,
        );
    }
    eq(
        r#"print(backtrack_find_all(" \nx", "\\s*\\n|\\s*x"), backtrack_find_all(" \nx", "(?:\\s*\\n|\\s*x)(?<!y)"))"#,
        r#"[" \n", "x"] [" \n", "x"]"#,
    );
    // Ronda 7, M-1: una rama que es la cuenta de algo que sólo coincide vacío también le llega
    // al motor lineal como una concatenación. Suelta daba `["a"]`; Perl y Python, `aa`.
    eq(
        r#"print(backtrack_find_all("aa", "\\b^(?:a|)aa|(?:\\b^a|(?:\\b^){2})"), backtrack_find_all("aa", "(?:\\b^(?:a|)aa|(?:\\b^a|(?:\\b^){2}))(?<!@)"))"#,
        r#"["aa"] ["aa"]"#,
    );
    // Ronda 8, M-1: lo mismo cuando lo que sólo coincide vacío es un `{0}` de algo sin tope
    // (suelta daba `["a"]`), y lo que apareció al arreglarla: lo que queda de un `{0}` cuando el
    // patrón va entero al motor lineal (suelta daba `["x", "x"]`).
    eq(
        r#"print(backtrack_find_all("aa", "\\b^(?:a|(?:a*){0})aa|(?:\\b^a|(?:\\b^(?:a*){0}){2})"), backtrack_find_all("aa", "(?<!@)(?:\\b^(?:a|(?:a*){0})aa|(?:\\b^a|(?:\\b^(?:a*){0}){2}))"))"#,
        r#"["aa"] ["aa"]"#,
    );
    eq(
        r#"print(backtrack_find_all("xx", "(?:a?b?){0}(?:x|)xx|(?:(?:a?b?){0}x|(?:a?b?){0})"), backtrack_find_all("xx", "(?:(?:a?b?){0}(?:x|)xx|(?:(?:a?b?){0}x|(?:a?b?){0}))(?<!@)"))"#,
        r#"["xx"] ["xx"]"#,
    );
    // el otro motor, el de siempre
    eq(r#"print(regex_find_all("ab", "a?a|a?b"), regex_find_all(" \nx", "\\s*\\n|\\s*x"))"#, r#"["ab"] [" \nx"]"#);
    // Gasta pasos. No los gasta lo que va al motor lineal: una alternancia de repeticiones
    // sueltas, una con una rama de largo fijo, una cuyas ramas empiezan distinto, y una cuyo
    // comienzo común termina en un solo lugar.
    err_has(
        r#"print(backtrack_find_all("ab", "a?a|a?b", max_steps = 1))"#,
        "backtrack_find_all: step limit exceeded (max_steps = 1) — ",
    );
    eq(
        r#"print(backtrack_find_all("ab 12", "\\w+|\\d+", max_steps = 1), backtrack_find_all("foo baar", "foo|ba+r", max_steps = 1))"#,
        r#"["ab", "12"] ["foo", "baar"]"#,
    );
    eq(
        r#"print(backtrack_find_all("foo bar baz  qux", "foo\\s+bar|baz\\s+qux", max_steps = 1), backtrack_find_all("foo baar", "\\bfoo\\b|\\bba+r\\b", max_steps = 1))"#,
        r#"["foo bar", "baz  qux"] ["foo", "baar"]"#,
    );
}

/// Ronda 8, propio: un grupo que sólo guarda su lugar (los de un bloque DEFINE, los de un `{0}`)
/// no le cambia el número a los demás, corra donde corra el patrón. La crate no contaba los
/// grupos de un bloque DEFINE al traducir para el motor lineal (los que venían después quedaban
/// con el número de uno del bloque), y con un look-ahead al final buscaba los grupos de un `{0}`
/// un número antes del que tienen.
#[test]
pub fn round8_groups_that_only_hold_a_place_do_not_move_the_others() {
    // después de un bloque DEFINE: daba `["1", nothing]`, y `[1|]` el reemplazo
    eq(
        r#"print(backtrack_capture("a1", "(?(DEFINE)(?<d>\\d))(a)\\g<d>"), backtrack_replace("a1 a2", "(?(DEFINE)(?<d>\\d))(a)\\g<d>", "[\\1|\\2]"))"#,
        r#"["1", "a"] [1|a] [2|a]"#,
    );
    // con el patrón entero en el motor lineal: daba `["c"]` en los dos
    eq(
        r#"print(backtrack_capture("c", "(?(DEFINE)(?<n>a)(?<m>b))(c)"), backtrack_capture("c", "(c)(?(DEFINE)(?<n>a)(?<m>b))"))"#,
        r#"[nothing, nothing, "c"] ["c", nothing, nothing]"#,
    );
    // y con un look-behind al lado (la VM arriba): daba `["c", nothing, nothing]`
    eq(r#"print(backtrack_capture("c", "(?<!@)(?(DEFINE)(?<n>a)(?<m>b))(c)"))"#, r#"[nothing, nothing, "c"]"#);
    // los grupos de un `{0}` con un look-ahead al final: daba `["", nothing]` y `["a", ""]`
    eq(
        r#"print(backtrack_capture("ab", "(x){0}(a)(?=b)"), backtrack_capture("ab", "(a)(x){0}(?=b)"), backtrack_replace("ab", "(x){0}(a)(?=b)", "[\\1|\\2]"))"#,
        r#"[nothing, "a"] ["a", nothing] [|a]b"#,
    );
    // sin el look-ahead, y con la VM, lo de siempre
    eq(
        r#"print(backtrack_capture("ab", "(x){0}(a)b"), backtrack_capture("ab", "(x){0}(a)(?=b)(?<!@)"))"#,
        r#"[nothing, "a"] [nothing, "a"]"#,
    );
}

/// Rondas 9 y 10: un grupo de captura adentro de un look-behind positivo de largo variable, o una
/// llamada (que escribe el grupo que llama), es un error de patrón inválido en las cuatro
/// funciones, y `try` lo atrapa. Lo que ese grupo guardaba dependía de cómo la crate compilaba el
/// cuerpo (`(?<=(a|ab))c` sobre `abc` daba `a`, y `(?<=(\d+));` sobre `12345;` daba `12345` o `5`
/// según lo que hubiera al lado), y la manera que da una sola cosa para todo cuerpo es
/// exponencial con un cuerpo ambiguo. De largo fijo, en uno negativo y sin grupos sigue como
/// estaba.
#[test]
pub fn round10_a_capture_group_in_a_look_behind_of_variable_length_is_an_error() {
    for pattern in [
        "(?<=(a|ab))c",
        r"(?<=(\d+));",
        r"(?<== (\d+|\d+\.\d+));",
        "(?<=(a)|(bc))x",
        r"(?<=((?:\w+\s?)+))!",
        r"(?(DEFINE)(?<g>\w))(?<=\g<g>\d+)!",
    ] {
        let want = format!(
            "invalid regex pattern '{}': Error compiling regex: A look-behind of variable length has a capture group or a \
             subroutine call in it: use (?:...) if the group is only for grouping, capture outside the look-behind, or \
             give the look-behind one fixed length",
            pattern.replace('\\', "\\\\")
        );
        let p = lit(pattern);
        for call in [
            format!("backtrack_find_all(\"abc\", {p})"),
            format!("backtrack_capture(\"abc\", {p})"),
            format!("backtrack_replace(\"abc\", {p}, \"x\")"),
            format!("backtrack_matches(\"abc\", {p})"),
            format!("backtrack_find_all(\"\", {p}, max_steps = 1)"),
        ] {
            let got = out(&format!("print({call})"));
            assert!(got.starts_with("ERR: ") && got.ends_with(&want), "{}\n→ {}", call, got);
            eq(&format!("try\n    print({call})\nrecover e\n    print(\"atrapado\")"), "atrapado");
        }
    }
    // lo que el mensaje propone: `(?:…)` si el paréntesis sólo agrupa, y capturar afuera con `\K`
    eq(r#"print(backtrack_find_all("abc", "(?<=(?:a|ab))c"), backtrack_capture("abc", "(a|ab)\\Kc"))"#, r#"["c"] ["ab"]"#);
    eq(
        r#"print(backtrack_capture("id: 12345;", "(\\d+)\\K;"), backtrack_find_all("id: 12345;", "(\\d+)\\K;"))"#,
        r#"["12345"] [";"]"#,
    );
    // de largo fijo hay un solo comienzo: con grupos y con una llamada
    eq(
        r#"print(backtrack_capture("cde", "(?<=(ab|cd))e"), backtrack_capture("a!", "(?(DEFINE)(?<g>\\w))(?<=\\g<g>)!"))"#,
        r#"["cd"] ["a"]"#,
    );
    // uno negativo no deja grupos
    eq(
        r#"print(backtrack_capture("cb ab", "(?<!(a+))b"), backtrack_capture("a1! !", "(?(DEFINE)(?<g>\\w))(?<!\\g<g>\\d+)!"))"#,
        "[nothing] [nothing]",
    );
    // y sin grupos sólo dice si coincide: el cuerpo ambiguo de la ronda 10 entra en mil pasos
    eq(
        r#"print(backtrack_find_all("bcx ax x", "(?<=a|bc)x"), backtrack_find_all("hola mundo esto es una frase larga!", "(?<=(?:\\w+\\s?)+)!", max_steps = 1000))"#,
        r#"["x", "x"] ["!"]"#,
    );
    // N-3: uno negativo con un grupo vacío bajo una cuenta coincidía de más (daba `["x"]`)
    eq(
        r#"print(backtrack_find_all("cx", "(?<!c+(){2,}?)x"), backtrack_find_all("x", "(?<!c+(){2,}?)x"))"#,
        r#"[] ["x"]"#,
    );
}

/// Ronda 10, B-1: una condición con las dos ramas vacías coincide diga lo que diga la condición.
/// La crate la leía como `(?(1))` sin ramas, que sigue sólo si el grupo participó.
#[test]
pub fn round10_a_conditional_with_two_empty_branches_matches_either_way() {
    // la primera daba `[]`
    eq(
        r#"print(backtrack_find_all("b", "(?:|(a))(?(1)|)b"), backtrack_find_all("ab", "(?:|(a))(?(1)|)b"), backtrack_find_all("b", "(a)?(?(1))b"))"#,
        r#"["b"] ["ab"] []"#,
    );
}

/// Ronda 11, M-1 y M-2: `\K` donde un look-around lo correría (escrito adentro, o en un grupo
/// que el look-around llama) es un error de patrón inválido en las cuatro funciones, y `try` lo
/// atrapa. La crate lo dejaba escribir el comienzo de la coincidencia desde adentro:
/// `backtrack_find_all("abc", "(?<=\\K\\w)\\w")` daba `["ab", "bc"]`, dos coincidencias que se
/// pisan, y `backtrack_replace` de lo mismo era el error interno del motor.
#[test]
pub fn round11_keep_out_where_a_look_around_would_run_it_is_an_error() {
    for pattern in [
        r"(?<=\K\w)\w",
        r"(?<=\Ka+)b",
        r"(?<=\Ka+(?:(?!)x)?)b",
        r"a(?=bc\K)b",
        r"(?<!\Ka)b",
        r"(?<k>a\Kb)(?=\g<k>)",
    ] {
        let want = format!(
            "invalid regex pattern '{}': Error compiling regex: A look-around has \\K in it, or calls a group that has it: \
             \\K sets where the match starts, and what a look-around reads is not part of the match; write \\K outside \
             the look-around",
            pattern.replace('\\', "\\\\")
        );
        let p = lit(pattern);
        for call in [
            format!("backtrack_find_all(\"abc\", {p})"),
            format!("backtrack_capture(\"abc\", {p})"),
            format!("backtrack_replace(\"abc\", {p}, \"-\")"),
            format!("backtrack_matches(\"abc\", {p})"),
            format!("backtrack_find_all(\"\", {p}, max_steps = 1)"),
        ] {
            let got = out(&format!("print({call})"));
            assert!(got.starts_with("ERR: ") && got.ends_with(&want), "{}\n→ {}", call, got);
            eq(&format!("try\n    print({call})\nrecover e\n    print(\"atrapado\")"), "atrapado");
        }
    }
    // un `\K` que ningún look-around corre sigue como estaba
    eq(
        r#"print(backtrack_find_all("ab ab", "a\\Kb"), backtrack_replace("ab ab", "a\\Kb", "-"), backtrack_capture("abc", "(a\\Kb)c"), backtrack_matches("ab", "a\\Kb"))"#,
        r#"["b", "b"] a- a- ["ab"] true"#,
    );
    // también en un grupo que se llama desde afuera de un look-around, y con un look-around que
    // llama a otro grupo
    eq(
        r#"print(backtrack_find_all("abab", "(a\\Kb)\\g<1>"), backtrack_find_all("aba", "(?<x>a)(?<y>b\\K)(?=\\g<x>)"))"#,
        r#"["b"] [""]"#,
    );
}

/// Ronda 11, B-1: lo que dice que una condición tiene dos ramas es la `|`. Sin ella, una rama
/// vacía no es una rama: `(?x)(?(1) )` y `(?(1)(?#c))` son `(?(1))`, que sigue sólo si el grupo
/// participó. El arreglo de la ronda 10 lo decidía por la posición en el texto, y las dos
/// coincidían siempre.
#[test]
pub fn round11_without_a_bar_an_empty_branch_of_a_conditional_is_no_branch() {
    // daban `["b"]` las tres
    eq(
        r#"print(backtrack_find_all("b", "(?x)(?:|(a))(?(1) )b"), backtrack_find_all("b", "(?:|(a))(?(1)(?#nada))b"), backtrack_find_all("b", "(?:|(a))(?(1)(?:))b"))"#,
        "[] [] []",
    );
    // con la `|`, coincide siempre; y sin ella, cuando el grupo participó
    eq(
        r#"print(backtrack_find_all("b", "(?x)(?:|(a))(?(1) | )b"), backtrack_find_all("ab", "(?x)(?:|(a))(?(1) )b"))"#,
        r#"["b"] ["ab"]"#,
    );
}

/// Ronda 12: las llamadas relativas al grupo 0 conservan los límites de la coincidencia.
#[test]
pub fn round12_relative_calls_to_group_zero_keep_the_match_bounds() {
    eq(
        r#"print(backtrack_find_all("xyxz", "x(?=y\\g<-1>|z)"), backtrack_replace("xyxz", "x(?=y\\g<-1>|z)", "-"), backtrack_capture("xyxz", "x(?=y\\g<-1>|z)"), backtrack_matches("xyxz", "x(?=y\\g<-1>|z)"))"#,
        r#"["x", "x"] -y-z ["x"] false"#,
    );
    eq(
        r#"print(backtrack_find_all("xyxz", "x(?=y\\g'-1'|z)"), backtrack_find_all("xyxz", "()x(?=y\\g<-2>|z)"))"#,
        r#"["x", "x"] ["x", "x"]"#,
    );
    for call in [r"\\g<-1>", r"\\g'-1'", r"\\g<0>"] {
        for invocation in [
            format!(r#"backtrack_find_all("aa", "a(?=(?<={call}.)|)")"#),
            format!(r#"backtrack_replace("aa", "a(?=(?<={call}.)|)", "-")"#),
            format!(r#"backtrack_capture("aa", "a(?=(?<={call}.)|)")"#),
            format!(r#"backtrack_matches("aa", "a(?=(?<={call}.)|)")"#),
        ] {
            err_has(&invocation, "A look-behind of variable length");
        }
    }
}

/// Ronda 6, M-2: una cuenta con el mínimo mayor que el máximo es un error de patrón inválido, en
/// las cuatro funciones, y `try` lo atrapa. La crate la leía como `{3}` en un motor y como `{2}`
/// en el otro (`a{3,2}` sobre `aaa`: `["aaa"]` suelto y `["aa"]` con un `(?<!x)` al lado), y en
/// un look-behind era un error del DFA. Las `regex_*` ya la rechazaban.
#[test]
pub fn round6_a_count_with_its_minimum_over_its_maximum_is_an_error() {
    for (pattern, at) in [("a{3,2}", 1), ("(a{1,0})*", 2), ("(?<=a{3,2})b", 5), ("a{3,2}(?<!x)", 1)] {
        let want = format!(
            "invalid regex pattern '{}': Parsing error at position {}: Repetition count has its minimum greater than its \
             maximum",
            pattern, at
        );
        let p = lit(pattern);
        for call in [
            format!("backtrack_find_all(\"aaab\", {p})"),
            format!("backtrack_capture(\"aaab\", {p})"),
            format!("backtrack_replace(\"aaab\", {p}, \"x\")"),
            format!("backtrack_matches(\"aaab\", {p})"),
            format!("backtrack_find_all(\"\", {p}, max_steps = 1)"),
        ] {
            let got = out(&format!("print({call})"));
            assert!(got.starts_with("ERR: ") && got.ends_with(&want), "{}\n→ {}", call, got);
            eq(&format!("try\n    print({call})\nrecover e\n    print(\"atrapado\")"), "atrapado");
        }
    }
    // en orden es la cuenta, y una llave sin nada adelante sigue siendo texto
    eq(r#"print(backtrack_find_all("aaaa {3,2}", "a{2,3}|{3,2}"))"#, r#"["aaa", "{3,2}"]"#);
    // las `regex_*` la rechazan, como antes
    err_has(r#"print(regex_find_all("aaa", "a{3,2}"))"#, "invalid repetition count range, the start must be <= the end");
}

/// Ronda 6, B-2 y N-2. Con `(?U)` un posesivo sigue siendo goloso, como en PCRE (la crate lo
/// dejaba perezoso y posesivo: tomaba lo mínimo y no lo devolvía). Y un comentario adentro de la
/// llave de una cuenta no se saltea: la llave es texto, como en Perl, PCRE2 y Python (la crate
/// leía la cuenta).
#[test]
pub fn round6_possessive_under_the_u_flag_and_a_comment_inside_a_count() {
    eq(
        r#"print(backtrack_find_all("aaa", "(?U)a++"), backtrack_find_all("aaa", "(?U)a*+"), backtrack_find_all("aaa", "(?U)a?+"))"#,
        r#"["aaa"] ["aaa"] ["a", "a", "a"]"#,
    );
    eq(
        r#"print(backtrack_find_all("aaa", "(?U)a+"), backtrack_find_all("aaa", "(?U)a+?"), backtrack_find_all("aaa", "(?U)a++a"))"#,
        r#"["a", "a", "a"] ["aaa"] []"#,
    );
    err_has(
        r#"print(backtrack_find_all("aaa", "(?U)a+?+"))"#,
        "invalid regex pattern '(?U)a+?+': Parsing error at position 7: Target of repeat operator is invalid",
    );
    eq(
        r#"print(backtrack_find_all("aa a{2}", "a{(?#c)2}"), backtrack_find_all("aa a{2}", "a(?#c){2}"), backtrack_find_all("aa", "(?x)a{ 2 }"))"#,
        r#"["a{2}"] ["aa"] ["aa"]"#,
    );
}

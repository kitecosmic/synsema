//! v0.6.56: `f32` desde un programa, fila por fila de `specs/v0.6.56-diseno.md` §3. Los valores
//! esperados salen de numpy 2.2.1 (`specs/v0.6.56-sondas/m1.py`, `m2.py`, `m3.py`) o del error
//! elegido (E1–E8, diseño §2).

fn run(src: &str) -> synsema_core::interpreter::RunResult {
    synsema_runtime::engine::run_source(src, "v0656.syn")
}

const W: &str = "let w be array([0.5, 1.5, -2.25], dtype = \"f32\")
let v be array([1, 2, 4], dtype = \"f32\")
let a be array([1, 2, 4])
let m be a > 1
let M be array([[1, 2], [3, 4]], dtype = \"f32\")
let t be array([0.1], dtype = \"f32\")
";

/// Lo impreso por `rest` (después de `W`), o `ERR: <error>`.
fn with_w(rest: &str) -> String {
    let r = run(&format!("{}{}", W, rest));
    if r.success {
        r.output.join("\n")
    } else {
        format!("ERR: {}", r.errors.join("\n"))
    }
}

fn eq(rest: &str, want: &str) {
    assert_eq!(with_w(rest), want, "{}", rest);
}

fn err_has(rest: &str, want: &str) {
    let out = with_w(rest);
    assert!(out.starts_with("ERR: ") && out.contains(want), "{}\n→ {}", rest, out);
}

const E1_F32_F64: &str = "cannot mix an f32 array and an f64 array — convert one first: astype(x, \"f32\") or astype(x, \"f64\")";
const E1_F64_F32: &str = "cannot mix an f64 array and an f32 array — convert one first: astype(x, \"f32\") or astype(x, \"f64\")";

// ---------- §3.1 crear y convertir ----------

#[test]
pub fn constructors_take_a_dtype() {
    eq("print(dtype(w))\nprint(dtype(a))", "f32\nf64");
    eq("print(dtype(astype(ones([2]), \"f32\")))", "f32");
    for c in ["zeros([2]", "ones([2]", "full([2], 0.1", "arange(0, 3", "linspace(0, 1, 3", "identity(2", "eye(2"] {
        eq(&format!("print(dtype({}, dtype = \"f32\")))", c), "f32");
        eq(&format!("print(dtype({}, dtype = \"f64\")))", c), "f64");
        eq(&format!("print(dtype({})))", c), "f64");
    }
    eq("print(to_list(full([1], 0.1, dtype = \"f32\")))", "[0.10000000149011612]");
    eq("print(to_list(array([1e40], dtype = \"f32\")))", "[inf]");
    // arange en `f32` es el `f64` redondeado (diseño §3.1).
    eq("print(arange(0, 3, 0.1, dtype = \"f32\") == astype(arange(0, 3, 0.1), \"f32\"))", "true");
    eq("print(linspace(0, 1, 7, dtype = \"f32\") == astype(linspace(0, 1, 7), \"f32\"))", "true");
}

#[test]
pub fn constructor_dtype_errors() {
    err_has("zeros([2], dtype = \"bool\")", "zeros: a mask is made by comparing — zeros(n) > 0, or astype(zeros(n), \"bool\")");
    err_has(
        "zeros([2], dtype = \"f16\")",
        "zeros: \"f16\" is a byte format, not an array dtype — array_from_bytes(b, \"f16\") reads it as f32",
    );
    err_has("ones([2], dtype = \"bf16\")", "ones: \"bf16\" is a byte format");
    err_has("zeros([2], dtype = \"i32\")", "zeros: dtype must be \"f64\" or \"f32\", got \"i32\"");
    err_has("array([1], dtype = 32)", "array: dtype must be \"f64\" or \"f32\", got 32");
}

#[test]
pub fn astype_follows_numpy_at_the_edges() {
    // numpy: [inf, -inf, nan, -0.0, 1.401298464324817e-45, 0.0]; 3.4028235677973366e38 → inf.
    eq(
        "print(to_list(astype(array([1e39, -1e39, nan, -0.0, 1e-45, 1e-46, 3.4028235677973366e38]), \"f32\")))",
        "[inf, -inf, nan, -0.0, 1.401298464324817e-45, 0.0, inf]",
    );
    eq("print(astype(w, \"f64\") == array([0.5, 1.5, -2.25]))", "true");
    eq("print(astype(m, \"f32\"))\nprint(dtype(astype(m, \"f32\")))", "[0, 1, 1]\nf32");
    eq("print(astype(array([0, nan, -0.0, 2], dtype = \"f32\"), \"bool\"))", "[false, true, false, true]");
    eq("print(astype(w, \"f32\") == w)", "true");
    err_has("astype([1, 2], \"f32\")", "astype expects an array, got list — make it an array first: array(xs)");
    err_has("astype(a, \"f16\")", "astype: \"f16\" is a byte format, not an array dtype");
    err_has("astype(a, \"i32\")", "astype: dtype must be \"f64\", \"f32\" or \"bool\", got \"i32\"");
}

#[test]
pub fn random_in_f32_is_the_f64_draw_rounded() {
    eq(
        "print(random_normal(rng(0), [5], dtype = \"f32\") == astype(random_normal(rng(0), [5]), \"f32\"))",
        "true",
    );
    eq(
        "print(random_uniform(rng(42), [5], dtype = \"f32\") == astype(random_uniform(rng(42), [5]), \"f32\"))",
        "true",
    );
    // numpy: default_rng(0).normal(size=3).astype(np.float32)[0] = 0.1257302165031433.
    eq("print(random_normal(rng(0), [3], dtype = \"f32\")[0])", "0.1257302165031433");
    eq("print(dtype(random_uniform(rng(1), [2, 2], dtype = \"f32\")))", "f32");
}

#[test]
pub fn bytes_keep_the_dtype() {
    eq("print(dtype(array_from_bytes(array_to_bytes(w), \"f32\")))", "f32");
    eq("print(length(array_to_bytes(w)))\nprint(length(array_to_bytes(w, \"f64\")))", "12\n24");
    eq("print(array_from_bytes(array_to_bytes(w), \"f32\") == w)", "true");
    // f16: 65504 es el máximo; 1e6 se va a inf; bf16 lee a f32.
    eq(
        "print(to_list(array_from_bytes(array_to_bytes(array([1.5, 65504, 1e6, 0.1]), \"f16\"), \"f16\")))",
        "[1.5, 65504.0, inf, 0.0999755859375]",
    );
    eq(
        "print(to_list(array_from_bytes(array_to_bytes(array([1.0, 3.140625, 0.1]), \"bf16\"), \"bf16\")))\nprint(dtype(array_from_bytes(array_to_bytes(w, \"bf16\"), \"bf16\")))",
        "[1.0, 3.140625, 0.10009765625]\nf32",
    );
    err_has("array_to_bytes(w, \"bool\")", "\"bool\" is for masks and this array is f32 — compare first: a != 0");
}

// ---------- §3.2 aritmética y mezcla ----------

#[test]
pub fn arithmetic_keeps_f32_and_rounds_the_loose_number_first() {
    eq("print(w + v)\nprint(dtype(w + v))", "[1.5, 3.5, 1.75]\nf32");
    eq("print(dtype(w * 0.5))\nprint(dtype(0.5 * w))\nprint(dtype(2 ** w))\nprint(dtype(w // 2))", "f32\nf32\nf32\nf32");
    // numpy: -2.2 · f32(0.1) redondeado a f32 = -0.2200000137090683 (no -2.2 · 0.1 redondeado).
    eq("print(to_list(array([-2.2], dtype = \"f32\") * 0.1))", "[-0.2200000137090683]");
    eq("print(to_list(zeros([1], dtype = \"f32\") + 16777217))", "[16777216.0]");
    eq("print(to_list(w * 1e40))", "[inf, inf, -inf]");
    eq("print(m * w)\nprint(dtype(m * w))\nprint(dtype(m * 1.0))", "[0, 1.5, -2.25]\nf32\nf64");
    eq("print(-w)\nprint(dtype(-w))", "[-0.5, -1.5, 2.25]\nf32");
    err_has("w + a", &format!("'+': {}", E1_F32_F64));
    err_has("a * w", &format!("'*': {}", E1_F64_F32));
    err_has("w + [1, 2, 3]", "cannot apply '+' between array and list");
}

// ---------- §3.3 comparaciones y == ----------

#[test]
pub fn comparisons_happen_in_f32() {
    eq("print(t > 0.1)\nprint(equal(t, 0.1))", "[false]\n[true]");
    eq("print(w > v)", "[false, false, false]");
    err_has("w < a", &format!("'<': {}", E1_F32_F64));
    err_has("equal(w, a)", &format!("equal: {}", E1_F32_F64));
    err_has("not_equal(a, w)", &format!("not_equal: {}", E1_F64_F32));
    err_has("w < m", "masks are not ordered");
    eq("print(w == array([0.5, 1.5, -2.25], dtype = \"f32\"))\nprint(w != v)", "true\ntrue");
    err_has(
        "w == a",
        "an f32 array and an f64 array are never equal — compare like with like: astype(x, \"f32\") or astype(x, \"f64\")",
    );
    err_has("w == m", "a mask and an f32 array are never equal — compare like with like (astype(m, \"f32\") gives 0/1 floats)");
    err_has("w == 0.1", "== compares whole values; for elementwise: equal(a, 0.1)");
    eq("print(w == nothing)\nprint(contains([a], astype(a, \"f32\")))", "false\nfalse");
    // F8: leer da un número de Synsema con el valor exacto del `f32`.
    eq("print(t[0] == 0.1)\nprint(t[0])\nprint(w[0] == 0.5)", "false\n0.10000000149011612\ntrue");
    eq("print(is_nan(w))", "[false, false, false]");
    err_has("logical_and(w, m)", "logical_and expects masks (bool arrays), got a f32 array — compare first: a > 0");
    err_has("where(a, w)", "where expects a mask (a > 0) or a predicate ((x) => …), got a f32 array");
}

// ---------- §3.4 elemento a elemento ----------

#[test]
pub fn elementwise_functions_keep_f32() {
    for f in ["exp(w)", "ln(v)", "sqrt(v)", "sin(w)", "tanh(w)", "abs(w)", "floor(w)", "round(w)", "erf(w)", "round_to(w, 1)", "sign(w)"] {
        eq(&format!("print(dtype({}))", f), "f32");
    }
    eq("print(to_list(sqrt(array([2], dtype = \"f32\"))))", "[1.4142135381698608]");
    eq("print(maximum(w, 0))\nprint(dtype(maximum(w, 0)))", "[0.5, 1.5, 0]\nf32");
    eq("print(clamp(w, 0, 1))\nprint(dtype(clamp(w, 0, 1)))", "[0.5, 1, 0]\nf32");
    eq("print(if_else(m, w, 0))\nprint(dtype(if_else(m, w, m)))", "[0, 1.5, -2.25]\nf32");
    eq("print(dtype(if_else(m, m, m)))\nprint(dtype(if_else(m, 1, 0)))", "bool\nf64");
    eq("print(pow(v, 2))\nprint(dtype(atan2(w, v)))", "[1, 4, 16]\nf32");
    err_has("maximum(w, a)", &format!("maximum: {}", E1_F32_F64));
    err_has("clamp(w, a, 1)", &format!("clamp: {}", E1_F32_F64));
    err_has("if_else(m, w, a)", &format!("if_else: {}", E1_F32_F64));
    err_has("pow(w, a)", &format!("pow: {}", E1_F32_F64));
    eq("print(dtype(apply(w, (x) => x * 0.1)))\nprint(dtype(apply(w, (x) => x > 0)))", "f32\nbool");
    eq("print(where(w, (x) => x > 0))\nprint(dtype(where(w, (x) => x > 0)))", "[0.5, 1.5]\nf32");
    // Ajuste 4: `where` con predicado conserva el tipo también para una máscara (el predicado ve bool).
    eq("print(where(m, (x) => x))\nprint(dtype(where(m, (x) => x)))", "[true, true]\nbool");
    eq("print(dtype(where(w, w > 0)))\nprint(dtype(fill_nan(w, 0.5)))", "f32\nf32");
    eq("print(some(w, (x) => x == 0.5))", "true");
}

// ---------- §3.5 reducciones, álgebra lineal y forma ----------

#[test]
pub fn reductions_accumulate_in_f64_and_round_once() {
    eq("print(sum(w))\nprint(min(w))\nprint(argmax(w))", "-0.25\n-2.25\n1");
    // f32(0.1) + f32(0.2) en f64, redondeado a f32: 0.30000001192092896.
    eq("print(sum(array([0.1, 0.2], dtype = \"f32\")))", "0.30000001192092896");
    eq("print(mean(array([0.1, 0.2], dtype = \"f32\")))", "0.15000000596046448");
    eq("print(product(array([0.1, 0.2], dtype = \"f32\")))", "0.020000001415610313");
    eq("print(dtype(sum(M, axis = 0)))\nprint(sum(M, axis = 0))", "f32\n[4, 6]");
    eq("print(dtype(mean(M, axis = 1)))\nprint(dtype(std(M, axis = 0)))", "f32\nf32");
    eq("print(cumsum(w))\nprint(dtype(cumsum(w)))\nprint(dtype(diff(w)))", "[0.5, 2, -0.25]\nf32\nf32");
    eq("print(sum(m))", "2");
}

#[test]
pub fn matmul_and_linear_algebra() {
    eq("print(matmul(M, M))\nprint(dtype(matmul(M, M)))", "[[7, 10], [15, 22]]\nf32");
    eq("let B be stack([M, M])\nprint(dtype(matmul(B, M)))\nprint(matmul(B, M)[1])", "f32\n[[7, 10], [15, 22]]");
    err_has("matmul(M, astype(M, \"f64\"))", &format!("matmul: {}", E1_F32_F64));
    err_has("matmul(stack([M, M]), astype(M, \"f64\"))", &format!("matmul: {}", E1_F32_F64));
    eq("print(dot(v, v))", "21.0");
    err_has("dot(v, a)", &format!("dot: {}", E1_F32_F64));
    eq("print(dtype(inv(M)))\nprint(det(M))\nprint(dtype(solve(M, array([1, 2], dtype = \"f32\"))))", "f32\n-2.0\nf32");
    err_has("solve(M, array([1, 2]))", &format!("solve: {}", E1_F32_F64));
    eq("print(dtype(svd(M).s))\nprint(dtype(lstsq(M, array([1, 2], dtype = \"f32\"))))", "f32\nf32");
    // F1: cov/corr/polyfit dan valores f32 (numpy sube a f64).
    eq("print(cov(array([0.1, 0.2, 0.4], dtype = \"f32\"), array([1, 2, 3], dtype = \"f32\")))", "0.15000000596046448");
    err_has("cov(w, a)", &format!("cov: {}", E1_F32_F64));
    eq("print(transpose(M))\nprint(dtype(reshape(w, [3, 1])))\nprint(dtype(M[[1, 0]]))\nprint(dtype(take(M, [0], axis = 1)))", "[[1, 3], [2, 4]]\nf32\nf32\nf32");
}

#[test]
pub fn concat_stack_and_index_add() {
    eq("print(dtype(concat([w, v])))\nprint(dtype(stack([w, v])))", "f32\nf32");
    err_has("concat([w, a])", &format!("concat: {}", E1_F32_F64));
    eq("print(concat([m, w]))\nprint(dtype(concat([m, w])))", "[0, 1, 1, 0.5, 1.5, -2.25]\nf32");
    // Ajuste 4: dos máscaras dan una máscara (hasta 0.6.55, f64 0/1).
    eq("print(concat([m, m]))\nprint(dtype(stack([m, m])))", "[false, true, true, false, true, true]\nbool");
    eq("print(index_add(zeros([2], dtype = \"f32\"), [0, 0, 1], 1))\nprint(dtype(index_add(zeros([2], dtype = \"f32\"), [0], v[0])))", "[2, 1]\nf32");
    err_has("index_add(zeros([2], dtype = \"f32\"), [0], array([1]))", &format!("index_add: {}", E1_F32_F64));
}

// ---------- §3.6 leer, escribir y mostrar ----------

#[test]
pub fn reading_and_writing_an_f32() {
    eq("print(to_list(t))", "[0.10000000149011612]");
    eq("each x in t\n    print(x)", "0.10000000149011612");
    eq("each r in M\n    print(dtype(r))", "f32\nf32");
    eq("let x be zeros([3], dtype = \"f32\")\nset x[0] to 0.1\nprint(x[0])\nprint(dtype(x))", "0.10000000149011612\nf32");
    eq("let X be zeros([2, 2], dtype = \"f32\")\nset X[0] to v[[0, 1]]\nset X[1][1] to 9\nprint(X)", "[[1, 2], [0, 9]]");
    err_has(
        "let x be zeros([3], dtype = \"f32\")\nset x[[0, 1, 2]] to a",
        "set: an f32 array holds f32 numbers, got an f64 array — convert it: astype(x, \"f32\")",
    );
    err_has("let x be zeros([3], dtype = \"f32\")\nset x[0] to true", "set: an f32 array holds numbers, got bool — use 1.0");
    err_has("let x be zeros([3], dtype = \"f32\")\nset x[[0, 1, 2]] to m", "set: an f32 array holds numbers, got a mask — use astype(m, \"f32\")");
    err_has("let b be zeros([3])\nset b[[0, 1, 2]] to w", &format!("set: {}", E1_F64_F32));
}

#[test]
pub fn printing_and_json_use_the_shortest_f32() {
    eq("print(array([0.1, 1 / 3], dtype = \"f32\"))", "[0.1, 0.33333334]");
    eq("print(ones([1000000], dtype = \"f32\"))", "array(shape=[1000000], 1000000 elements, f32)");
    eq("print(json_encode(array([0.1, 1 / 3], dtype = \"f32\")))", "[0.1, 0.33333334]");
    // Ida y vuelta: el decimal más corto vuelve al mismo f32.
    eq(
        "let u be array([0.1, 1 / 3, 1e-8], dtype = \"f32\")\nprint(astype(array(json_decode(json_encode(u))), \"f32\") == u)",
        "true",
    );
}

// ---------- linaje (diseño §3.6, receta "ndarray") ----------

/// Un array que entra a una consulta se compromete con `encoding: "ndarray"`: `json_encode` del
/// valor con cada array como `{dtype, shape, data}`. `f32` ≠ `f64` y array ≠ lista.
#[test]
pub fn lineage_commits_arrays_with_dtype_and_shape() {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("synsema-v0656-lin-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("s.db").to_string_lossy().replace('\\', "/");
    let r = run(&format!(
        r#"require db("{db}")
db_open("{db}")
sql_exec("CREATE TABLE t (a TEXT)")
let q be "SELECT count(*) AS n FROM t WHERE a = ?"
let x32 be array([1, 0.5], dtype = "f32")
let x64 be array([1, 0.5])
sql(q, [x32])
sql(q, [x64])
sql(q, [[1, 0.5]])
let l be lineage()
print(l[0].committed_encoding, l[1].committed_encoding, l[2].committed_encoding)
task commit(e, payload)
    give "query sha256-salted:" + slice(hex(sha256(bytes(e.salt, "hex") + bytes(payload, "utf8"))), 2)
let r32 be json_encode([q, [{{"dtype": "f32", "shape": [2], "data": [1.0, 0.5]}}]])
let r64 be json_encode([q, [{{"dtype": "f64", "shape": [2], "data": [1.0, 0.5]}}]])
print(commit(l[0], r32) == l[0].what, commit(l[1], r64) == l[1].what)
print(commit(l[0], r64) == l[0].what, commit(l[2], canonical_json([q, [[1, 0.5]]])) == l[2].what)"#
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["ndarray ndarray jcs", "true true", "false true"]);
}

/// Una task caliente con aritmética de `f32`: el JIT la compila (en `v0656_f32_modes`, con el nivel
/// nativo instalado y `eager`) y tiene que dar lo mismo que la VM y el tree-walker.
#[test]
pub fn hot_task_compiles_f32_arithmetic() {
    eq(
        "task step(x, k)
    give x * 0.5 + k * x - 0.1
let y be w
each i in range(200)
    set y to step(w, 0.25)
print(y)
print(dtype(y))
print(to_list(y))",
        "[0.275, 1.025, -1.7875]
f32
[0.2750000059604645, 1.024999976158142, -1.787500023841858]",
    );
}

/// Las filas de §3 que faltaban (`specs/v0.6.56-sondas/t11_ref.py`, numpy 2.2.1: en `f64` desde los
/// valores `f32` y redondeado una vez).
#[test]
pub fn remaining_rows_of_the_table() {
    let x = "let x be array([0.5, 1.5, -2.25, 0.1], dtype = \"f32\")\nlet y be array([1, 2, 4, 3], dtype = \"f32\")\n";
    let e = |rest: &str, want: &str| eq(&format!("{}{}", x, rest), want);
    let bad = |rest: &str, want: &str| err_has(&format!("{}{}", x, rest), want);
    // Posiciones: enteros (§4).
    e("print(argmin(x), type_of(argmin(x)), argmax(x))", "2 number 1");
    // minimum: f32, y NaN se propaga.
    e("print(minimum(x, y))\nprint(dtype(minimum(x, y)))", "[0.5, 1.5, -2.25, 0.1]\nf32");
    e("print(minimum(array([nan, 1], dtype = \"f32\"), 0))", "[nan, 0]");
    bad("minimum(x, array([1.0, 2, 3, 4]))", &format!("minimum: {}", E1_F32_F64));
    // corr / polyfit: f32 (F1, numpy sube a float64); polyfit da la lista de coeficientes.
    e("print(corr(x, y))", "-0.7844297289848328");
    e("print(polyfit(x, y, 1))", "[-0.6376476287841797, 2.476088285446167]");
    bad("corr(x, array([1.0, 2, 3, 4]))", &format!("corr: {}", E1_F32_F64));
    // polyval: f32 sobre f32; sobre una máscara sola sigue siendo f64; con un f64 es E1.
    e(
        "print(to_list(polyval([1, 0.1], x)))\nprint(dtype(polyval([1, 0.1], x)))",
        "[0.6000000238418579, 1.600000023841858, -2.1500000953674316, 0.20000000298023224]\nf32",
    );
    e("print(dtype(polyval([1, 0.1], array([1, 2]) > 0)))", "f64");
    bad("polyval(array([1, 0.1], dtype = \"f32\"), array([1.0, 2]))", &format!("polyval: {}", E1_F32_F64));
    // norm y trace: un número redondeado a f32 (numpy suma por pares en f32: 2.7518177032470703).
    e("print(norm(x))\nprint(trace(array([[1, 2], [3, 4]], dtype = \"f32\")))", "2.751817464828491\n5.0");
    // histogram: conteos enteros; los bordes son números f64 (§4).
    e("print(histogram(x, 2))", "{counts: [1, 3], edges: [-2.25, -0.375, 1.5]}");
    // factorial y gcd: la regla de enteros de hoy, en f32.
    e(
        "let n be array([3, 4], dtype = \"f32\")\nprint(factorial(n), dtype(factorial(n)))\nprint(gcd(array([12, 18], dtype = \"f32\"), array([8, 12], dtype = \"f32\")))",
        "[6, 24] f32\n[4, 6]",
    );
    bad("gcd(array([4], dtype = \"f32\"), array([2.0]))", &format!("gcd: {}", E1_F32_F64));
    // text(w): el decimal más corto del f32.
    e("print(text(array([0.1, 1 / 3], dtype = \"f32\")) == \"[0.1, 0.33333334]\")", "true");
}

/// Los bordes que encontró la auditoría (ronda 1: N2, M2, M4).
#[test]
pub fn audit_round1_edges() {
    // Ronda 2 (N3): la uniforme f32 vive en [f32(low), f32(high)): desde el lenguaje `u >= low` y
    // `u < high` (que redondean el número suelto a f32, F3) son siempre verdad. Si el redondeo llega a
    // f32(high), la muestra es el f32 anterior. (low, high, máximo esperado).
    for (low, high, top) in [
        ("0.69999", "0.7", "0.6999999284744263"),
        ("0.0999999", "0.1", "0.09999999403953552"),
        ("-0.70001", "-0.7", "-0.7000000476837158"),
        ("0", "3e-45", "1.401298464324817e-45"),
    ] {
        eq(
            &format!("let u be random_uniform(rng(7), [20000], low = {low}, high = {high}, dtype = \"f32\")\nprint(every(u < {high}), every(u >= {low}), max(u))"),
            &format!("true true {top}"),
        );
    }
    eq(
        "let u be random_uniform(rng(7), [20000], dtype = \"f32\")\nprint(every(u < 1), every(u >= 0), max(u) < 1)",
        "true true true",
    );
    // Si low y high redondean al mismo f32, [low, high) está vacío en f32: error (en f64 sigue valiendo).
    err_has(
        "random_uniform(rng(7), [3], low = 1e-45, high = 2e-45, dtype = \"f32\")",
        "random_uniform: low = 1e-45 and high = 2e-45 round to the same f32, so [low, high) is empty in f32 — widen the interval or use dtype = \"f64\"",
    );
    eq("print(shape(random_uniform(rng(7), [3], low = 1e-45, high = 2e-45)))", "[3]");
    // Ronda 3 (M2): los números del error se escriben como `print` (no como Rust).
    err_has(
        "random_uniform(rng(7), [3], low = 3e38, high = 3.0000001e38, dtype = \"f32\")",
        "random_uniform: low = 3e+38 and high = 3.0000001e+38 round to the same f32",
    );
    err_has(
        "random_uniform(rng(7), [3], low = -0.0, high = 1e-46, dtype = \"f32\")",
        "random_uniform: low = -0.0 and high = 1e-46 round to the same f32",
    );
    err_has(
        "random_uniform(rng(7), [3], low = 1, high = 1.00000001, dtype = \"f32\")",
        "random_uniform: low = 1 and high = 1.00000001 round to the same f32",
    );
    err_has(
        "random_uniform(rng(7), [3], low = -1e308, high = 1e308)",
        "random_uniform: high - low must be finite, got low = -1e+308 and high = 1e+308",
    );
    // Ronda 3 (M3): una muestra f32 es siempre finita. Por arriba, f32(3.5e38) es inf y la muestra más
    // alta es f32::MAX; por abajo, f32(-3.5e38) es -inf y una muestra que redondea a -inf es -f32::MAX.
    eq(
        "let u be random_uniform(rng(7), [20000], low = -3.5e38, high = 0, dtype = \"f32\")\nprint(min(u), every(u >= -3.5e38), every(u < 0))",
        "-3.4028234663852886e+38 true true",
    );
    eq(
        "let u be random_uniform(rng(7), [20000], low = 0, high = 3.5e38, dtype = \"f32\")\nprint(max(u), every(u < 3.5e38))",
        "3.4028234663852886e+38 true",
    );
    // Ronda 4 (M1): con el intervalo invertido, finita de los dos lados.
    eq(
        "let u be random_uniform(rng(7), [20000], low = 3.5e38, high = 0, dtype = \"f32\")\nlet d be random_uniform(rng(7), [20000], low = 0, high = -3.5e38, dtype = \"f32\")\nprint(max(u), min(d))",
        "3.4028234663852886e+38 -3.4028234663852886e+38",
    );
    // Fuera de f32(high), la muestra es la de astype: difieren justo las que astype lleva a f32(0.7).
    eq(
        "let u be random_uniform(rng(7), [20000], low = 0.69999, high = 0.7, dtype = \"f32\")\nlet a be astype(random_uniform(rng(7), [20000], low = 0.69999, high = 0.7), \"f32\")\nlet top be sum(equal(a, 0.7))\nprint(sum(equal(u, a)) + top == 20000, top > 0)",
        "true true",
    );
    // M2: cumsum arranca en -0.0 (numpy: [-0.0, -0.0]); dot de vectores vacíos da 0.0 (BLAS).
    eq(
        "let c be cumsum(array([-0.0, -0.0], dtype = \"f32\"))\nprint(atan2(c[0], -1), atan2(c[1], -1), dtype(c))\nprint(atan2(cumsum(array([-0.0]))[0], -1))",
        "-3.141592653589793 -3.141592653589793 f32\n-3.141592653589793",
    );
    // El signo del cero se lee con atan2(z, -1): -pi para -0.0, pi para 0.0.
    eq(
        "print(atan2(dot(array([]), array([])), -1), atan2(dot(astype(array([]), \"f32\"), astype(array([]), \"f32\")), -1))",
        "3.141592653589793 3.141592653589793",
    );
    // M4: los coeficientes de una lista se redondean a f32 primero (F3), como en un array f32.
    eq(
        "let x be array([0.5, 1.5, -2.25], dtype = \"f32\")\nprint(to_list(polyval([0.1, 0.3], x)))\nprint(polyval([0.1, 0.3], x) == polyval(array([0.1, 0.3], dtype = \"f32\"), x))",
        "[0.3500000238418579, 0.45000001788139343, 0.07500001043081284]\ntrue",
    );
}

/// Todas las filas, para correrlas en jit, vm y ref (`tests/v0656_f32_modes.rs`; en `it` no se usa).
#[allow(dead_code)]
pub const ALL: &[(&str, fn())] = &[
    ("constructors_take_a_dtype", constructors_take_a_dtype),
    ("constructor_dtype_errors", constructor_dtype_errors),
    ("astype_follows_numpy_at_the_edges", astype_follows_numpy_at_the_edges),
    ("random_in_f32_is_the_f64_draw_rounded", random_in_f32_is_the_f64_draw_rounded),
    ("bytes_keep_the_dtype", bytes_keep_the_dtype),
    ("arithmetic_keeps_f32_and_rounds_the_loose_number_first", arithmetic_keeps_f32_and_rounds_the_loose_number_first),
    ("comparisons_happen_in_f32", comparisons_happen_in_f32),
    ("elementwise_functions_keep_f32", elementwise_functions_keep_f32),
    ("reductions_accumulate_in_f64_and_round_once", reductions_accumulate_in_f64_and_round_once),
    ("matmul_and_linear_algebra", matmul_and_linear_algebra),
    ("concat_stack_and_index_add", concat_stack_and_index_add),
    ("reading_and_writing_an_f32", reading_and_writing_an_f32),
    ("printing_and_json_use_the_shortest_f32", printing_and_json_use_the_shortest_f32),
    ("lineage_commits_arrays_with_dtype_and_shape", lineage_commits_arrays_with_dtype_and_shape),
    ("hot_task_compiles_f32_arithmetic", hot_task_compiles_f32_arithmetic),
    ("remaining_rows_of_the_table", remaining_rows_of_the_table),
    ("audit_round1_edges", audit_round1_edges),
];

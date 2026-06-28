//! Conformidad de Redis (M4, backend KV/cache/estructuras — 3er paradigma) bajo la API propia
//! `redis_*`.
//!
//! Los tests de **capability/routing** corren SIEMPRE (sin servidor): el chequeo de `db(scope)`
//! precede a la conexión, y un connstring a un puerto muerto falla con un error de RED — no de
//! capability — lo que prueba que el gate pasó y el ruteo a Redis funciona. Los de
//! **KV/TTL/estructuras/lock/binario** necesitan un Redis real → `#[ignore]`, gated por
//! `REDIS_URL`. Corre: `cargo test --test engine_redis -- --ignored` con
//! `REDIS_URL=redis://localhost:6379` seteada (scope `redis://localhost`).

use synsema_runtime::engine::run_source;

fn redis_url() -> Option<String> {
    std::env::var("REDIS_URL")
        .ok()
        .filter(|u| u.starts_with("redis://") || u.starts_with("rediss://"))
}

// =========================================================
// Capability + routing (sin servidor)
// =========================================================

/// `db_open("redis://…")` sin `require db` → violación con el scope canónico (sin
/// credenciales/puerto/query). Tampoco se auto-otorga en run. Gotcha del db-index: con `/0` el
/// scope trae el db (`redis://localhost/0`).
#[test]
fn redis_db_open_deny_without_require() {
    let r = run_source("db_open(\"redis://user:pw@localhost:6379/0\")", "<t>");
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"redis://localhost/0\")".to_string()]
    );
}

/// Gotcha del db-index: SIN `/N` el scope NO trae db (`redis://localhost`), distinto de `/0`.
#[test]
fn redis_db_open_scope_without_db_index() {
    let r = run_source("db_open(\"redis://localhost:6379\")", "<t>");
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"redis://localhost\")".to_string()]
    );
}

/// El scope URL es fiel: una grant a un db-index no cubre otro.
#[test]
fn redis_scope_mismatch_deny() {
    let r = run_source(
        "require db(\"redis://localhost/0\")\ndb_open(\"redis://localhost:6379/1\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"redis://localhost/1\")".to_string()]
    );
}

/// Con el grant adecuado el gate pasa y se rutea a Redis; el puerto muerto da un error de RED —
/// no de capability — → prueba "pasó el gate + ruteo a Redis" sin un servidor real.
#[test]
fn redis_gate_passes_routing_to_redis() {
    let r = run_source("require db\ndb_open(\"redis://127.0.0.1:59999\")", "<t>");
    assert!(!r.success, "conectar a un puerto muerto debe fallar");
    assert!(
        !r.errors.iter().any(|e| e.contains("Capability not granted")),
        "no debe ser violación de capability (el gate pasó): {:?}",
        r.errors
    );
}

/// `sandbox` despoja la capability `db`: un `db_open` adentro queda denegado (el gate falla antes
/// de conectar → sin servidor).
#[test]
fn redis_sandbox_strips_db() {
    let r = run_source(
        "require db(\"redis://localhost/0\")\nsandbox\n    db_open(\"redis://localhost:6379/0\")",
        "<t>",
    );
    assert!(!r.success, "el sandbox debería denegar db");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted")),
        "debe ser violación de capability: {:?}",
        r.errors
    );
}

/// `json_encode`/`json_decode` (compañeros de la API de DB para datos estructurados — builtins
/// generales, sin servidor): round-trip de un map anidado.
#[test]
fn json_encode_decode_roundtrip() {
    let r = run_source(
        "let m be json_decode(json_encode({\"a\": 1, \"b\": [2, 3], \"c\": \"x\"}))\n\
         print(text(m[\"a\"]))\n\
         print(text(length(m[\"b\"])))\n\
         print(m[\"c\"])\n",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["1", "2", "x"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// `json_decode` de un JSON inválido → error claro.
#[test]
fn json_decode_invalid_errors() {
    let r = run_source("let x be json_decode(\"{not json\")\n", "<t>");
    assert!(!r.success, "json_decode de JSON inválido debe fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("json_decode") && e.contains("invalid")),
        "el error debe mencionar json_decode/invalid: {:?}",
        r.errors
    );
}

// =========================================================
// KV / TTL / contadores / estructuras / lock / binario (requieren Redis real → #[ignore])
// =========================================================

/// KV + cache: set/get/del/exists + contadores (incr/decr/incrby) + TTL (ttl/persist; `-1` sin
/// TTL, `-2` clave inexistente).
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_kv_ttl_counters() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_m4\")\n\
         redis_set(\"syn_m4\", \"hola\")\n\
         print(redis_get(\"syn_m4\"))\n\
         print(text(redis_exists(\"syn_m4\")))\n\
         print(text(redis_del(\"syn_m4\")))\n\
         print(text(redis_get(\"syn_m4\") == nothing))\n\
         redis_set(\"syn_m4c\", \"10\")\n\
         print(text(redis_incr(\"syn_m4c\")))\n\
         print(text(redis_decr(\"syn_m4c\")))\n\
         print(text(redis_incrby(\"syn_m4c\", 5)))\n\
         redis_del(\"syn_m4c\")\n\
         redis_set(\"syn_m4t\", \"v\", 100)\n\
         print(type_of(redis_ttl(\"syn_m4t\")))\n\
         redis_persist(\"syn_m4t\")\n\
         print(text(redis_ttl(\"syn_m4t\")))\n\
         redis_del(\"syn_m4t\")\n\
         print(text(redis_ttl(\"syn_m4t\")))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "hola",   // get
            "1",      // exists
            "1",      // del (1 borrada)
            "true",   // get tras del → nothing
            "11",     // incr 10 → 11
            "10",     // decr 11 → 10
            "15",     // incrby +5 → 15
            "number", // ttl es number
            "-1",     // tras persist: sin TTL
            "-2",     // clave inexistente
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// `mset` (map) + `mget` (list, con clave ausente → nothing).
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_mget_mset() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_k1\")\n\
         redis_del(\"syn_k2\")\n\
         redis_mset({{\"syn_k1\": \"v1\", \"syn_k2\": \"v2\"}})\n\
         let vals be redis_mget([\"syn_k1\", \"syn_k2\", \"syn_missing\"])\n\
         print(vals[0])\n\
         print(vals[1])\n\
         print(text(vals[2] == nothing))\n\
         redis_del(\"syn_k1\")\n\
         redis_del(\"syn_k2\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["v1", "v2", "true"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// Hashes: hset (campos nuevos) / hget / hincrby / hgetall (map) / hdel.
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_hashes() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_h\")\n\
         print(text(redis_hset(\"syn_h\", {{\"a\": \"1\", \"b\": \"2\"}})))\n\
         print(redis_hget(\"syn_h\", \"a\"))\n\
         print(text(redis_hincrby(\"syn_h\", \"a\", 5)))\n\
         let all be redis_hgetall(\"syn_h\")\n\
         print(all[\"b\"])\n\
         print(text(contains(all, \"a\")))\n\
         print(text(redis_hdel(\"syn_h\", \"a\", \"b\")))\n\
         redis_del(\"syn_h\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "2",    // hset: 2 campos nuevos
            "1",    // hget a
            "6",    // hincrby a +5
            "2",    // hgetall["b"]
            "true", // contains a
            "2",    // hdel a,b
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// Listas (colas/pilas): rpush / llen / lpop / rpop / lrange.
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_lists() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_q\")\n\
         print(text(redis_rpush(\"syn_q\", \"a\", \"b\", \"c\")))\n\
         print(text(redis_llen(\"syn_q\")))\n\
         print(redis_lpop(\"syn_q\"))\n\
         print(redis_rpop(\"syn_q\"))\n\
         let r be redis_lrange(\"syn_q\", 0, -1)\n\
         print(text(length(r)))\n\
         print(r[0])\n\
         redis_del(\"syn_q\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "3", // rpush → long 3
            "3", // llen
            "a", // lpop (izq)
            "c", // rpop (der)
            "1", // queda [b]
            "b", // lrange[0]
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// Sets: sadd (dedup) / sismember / smembers / srem.
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_sets() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_s\")\n\
         print(text(redis_sadd(\"syn_s\", \"x\", \"y\", \"x\")))\n\
         print(text(redis_sismember(\"syn_s\", \"x\")))\n\
         print(text(redis_sismember(\"syn_s\", \"z\")))\n\
         print(text(length(redis_smembers(\"syn_s\"))))\n\
         print(text(redis_srem(\"syn_s\", \"x\")))\n\
         redis_del(\"syn_s\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "2",     // sadd: x,y (la 2ª x es dup)
            "true",  // sismember x
            "false", // sismember z
            "2",     // smembers length
            "1",     // srem x
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// `type` y `keys` (glob). KEYS es O(N) → en prod, patrón acotado.
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_type_and_keys() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_tk\")\n\
         redis_set(\"syn_tk\", \"v\")\n\
         print(redis_type(\"syn_tk\"))\n\
         print(text(contains(redis_keys(\"syn_tk\"), \"syn_tk\")))\n\
         redis_del(\"syn_tk\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["string", "true"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// Binario byte-exacto: set de un valor no-UTF8 (`0xFF`) → get devuelve `bytes` idéntico.
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_binary_roundtrip() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_bin\")\n\
         let raw be bytes(\"/w==\", \"base64\")\n\
         redis_set(\"syn_bin\", raw)\n\
         let back be redis_get(\"syn_bin\")\n\
         print(type_of(back))\n\
         print(text(decode(back, \"base64\") == \"/w==\"))\n\
         redis_del(\"syn_bin\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["bytes", "true"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// Lock distribuido: `redis_lock` da token; el 2º sobre la misma clave da `nothing`; `redis_unlock`
/// libera SOLO con el token correcto (Lua); tras liberar, se puede re-adquirir.
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_lock_unlock() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_lock\")\n\
         let tok be redis_lock(\"syn_lock\", 10000)\n\
         print(type_of(tok))\n\
         let tok2 be redis_lock(\"syn_lock\", 10000)\n\
         print(text(tok2 == nothing))\n\
         print(text(redis_unlock(\"syn_lock\", \"wrong-token\")))\n\
         print(text(redis_unlock(\"syn_lock\", tok)))\n\
         let tok3 be redis_lock(\"syn_lock\", 10000)\n\
         print(type_of(tok3))\n\
         redis_unlock(\"syn_lock\", tok3)\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "text",  // tok: adquirido
            "true",  // 2º intento: nothing (ya tomado)
            "false", // unlock con token ajeno: no libera
            "true",  // unlock con el token correcto: libera
            "text",  // re-adquirido tras liberar
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
}

/// Datos estructurados en Redis vía `json_encode`/`json_decode` (el patrón idiomático y auditable).
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn redis_json_structured() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         redis_del(\"syn_cfg\")\n\
         redis_set(\"syn_cfg\", json_encode({{\"theme\": \"dark\", \"n\": 3}}))\n\
         let cfg be json_decode(redis_get(\"syn_cfg\"))\n\
         print(cfg[\"theme\"])\n\
         print(text(cfg[\"n\"]))\n\
         redis_del(\"syn_cfg\")\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["dark", "3"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// `sql()` sobre una conexión Redis → error claro (sin sorpresas silenciosas).
#[test]
#[ignore = "requiere un Redis real (REDIS_URL)"]
fn sql_over_redis_errors() {
    let url = redis_url().expect("REDIS_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         let r be sql(\"SELECT 1\")\n"
    );
    let r = run_source(&src, "<t>");
    assert!(!r.success, "sql() sobre Redis debe fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("Redis connection") && e.contains("redis_")),
        "el error debe orientar a usar redis_*: {:?}",
        r.errors
    );
}

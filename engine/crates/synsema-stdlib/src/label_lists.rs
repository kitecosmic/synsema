//! Las listas de clasificación de etiquetas (tanda TEE): qué builtins son sumideros públicos,
//! cuáles sólo existen bajo `serve`, cuáles leen del SO y cuáles son puros. Vivían en
//! `synsema-runtime/src/engine.rs`; desde v0.6.45 (D1) viven acá para que el nativo y el wasm
//! (`synsema-wasm`, que no puede depender del runtime) registren sus sumideros desde la MISMA lista
//! — antes el wasm encendía las etiquetas sin registrar ningún sumidero y `http`/`state_set` hacia el
//! host salían sin chequeo. El runtime las reexporta con el mismo nombre (`engine::LABEL_*`); el
//! anti-rot `every_effectful_family_is_a_label_sink` (runtime) y su par del wasm las cruzan con lo
//! registrado de verdad.

/// Builtins del stdlib/agents/runtime que tienen EFECTO fuera del
/// programa (archivos, red, bases de datos, sockets, procesos, memoria persistente, entorno,
/// Programas hijos, notificaciones, attestation, gasto): bajo etiquetas son sumideros públicos.
/// Sumar un builtin con efecto sin listarlo acá lo deja fuera del chequeo: el test
/// `every_effectful_family_is_a_label_sink` cruza esta lista con las familias registradas.
pub const LABEL_SINK_BUILTINS: &[&str] = &[
    // Archivos y procesos (synsema-capabilities/secure.rs, stdlib/proc.rs, watch.rs, term.rs)
    "write_file", "append_file", "edit_file", "delete_file", "delete_dir", "read_file", "read_file_bytes",
    "list_dir", "file_exists", "file_info", "grep", "run", "run_program",
    "proc_spawn", "proc_send", "proc_close_stdin", "proc_kill", "proc_resize", "proc_wait", "proc_close",
    "watch", "watch_close", "term_open", "term_write", "term_close", "shutdown",
    // Red (stdlib/http.rs, ws.rs, webpush.rs, oidc.rs, blockchain_*_rpc.rs). `http` (el verbo
    // genérico) faltaba: lo encontró el anti-rot cruzando la lista con lo registrado.
    "http", "http_get", "http_post", "http_put", "http_delete", "http_bytes", "fetch",
    "mtls_identity",
    "ws_connect", "ws_send", "ws_broadcast", "ws_close", "push_send", "oidc_verify",
    // v0.6.42: TCP crudo y pipes (un pipe cruza a otro intérprete: escribir y cerrar son salidas).
    "tcp_connect", "tcp_send", "tcp_close", "pipe_send", "pipe_close",
    // v0.6.45 (A4): escribir sin esperar también es una salida.
    "tcp_write", "pipe_write",
    "eth_rpc", "eth_call", "eth_send_raw", "eth_balance", "eth_nonce", "eth_receipt", "eth_wait_receipt",
    "eth_estimate_gas", "eth_gas_price", "eth_fee_history", "eth_chain_id",
    "solana_rpc", "solana_send", "solana_confirm", "solana_balance", "solana_latest_blockhash", "spl_balance",
    "algorand_send", "algorand_wait", "algorand_account", "algorand_params",
    "btc_rpc", "btc_send", "btc_utxos", "btc_balance", "btc_fee_estimates", "btc_wait",
    // v0.6.29: `<familia>_<acción>` (los nombres de arriba quedan como alias hasta v1.0).
    "evm_rpc", "evm_call", "evm_send", "evm_balance", "evm_nonce", "evm_receipt", "evm_wait",
    "evm_estimate_gas", "evm_gas_price", "evm_fee_history", "evm_chain_id", "evm_block_number", "evm_logs",
    "solana_wait",
    // Bases de datos (stdlib/database.rs)
    "db_open", "db_close", "sql", "sql_exec", "sql_batch", "sql_tables", "paged",
    "redis_get", "redis_set", "redis_del", "redis_incr", "redis_incrby", "redis_decr", "redis_exists", "redis_expire",
    "redis_persist", "redis_ttl", "redis_type", "redis_keys", "redis_mget", "redis_mset", "redis_hget", "redis_hset",
    "redis_hdel", "redis_hgetall", "redis_hincrby", "redis_lpush", "redis_rpush", "redis_lpop", "redis_rpop",
    "redis_lrange", "redis_llen", "redis_sadd", "redis_srem", "redis_smembers", "redis_sismember", "redis_lock", "redis_unlock",
    "mongo_find", "mongo_find_one", "mongo_insert", "mongo_insert_many", "mongo_update", "mongo_delete",
    "mongo_count", "mongo_aggregate", "mongo_collections",
    // Memoria persistente, estado y progreso (synsema-agents, serve)
    "remember", "recall", "forget_memory", "add_rule", "create_progress", "start_step", "complete_step", "fail_step",
    "state_set", "state_get", "state_incr", "state_delete", "state_all", "state_merge", "state_cas",
    // Bus, cron, entorno, gasto, attestation, archivos comprimidos, exportes
    "bus_publish", "bus_subscribe", "bus_unsubscribe", "cron_every", "cron_after", "cron_cancel",
    "env", "secret", "reveal", "spend", "attest", "attest_key",
    // Agentes (sólo con swarm cableado) y fan-out a otros intérpretes. `parallel_map` es un
    // SUMIDERO, no `label_aware`: rechaza argumentos etiquetados ANTES de lanzar un worker. Es
    // fail-closed deliberado, no una imposibilidad (`SendValue::Private` existe desde el cierre
    // del snapshot de `serve`); la nota de `parallel.rs` explica qué habría que especificar para
    // hacerlo consciente. Sin esto el mapper recibía el valor ya despojado y hacía el efecto EN
    // CLARO mientras el resultado volvía etiquetado: la fuga parecía rastreada.
    "agent_stop", "parallel_map",
    "zip_create", "zip_extract", "tar_create", "tar_extract", "svg_to_png", "svg_to_pdf",
];

/// De las listas anteriores, los que NO existen en un intérprete de `run` pelado porque el runtime los
/// registra más tarde: bajo `serve` (estado compartido, por worker) o con un swarm cableado (agentes).
/// El anti-rot no puede buscarlos en el wiring base. La sentencia `emit` y la respuesta HTTP son
/// sumideros del propio `serve` (`serve.rs`/`routing.rs`), no builtins.
pub const LABEL_SINKS_SERVE_ONLY: &[&str] =
    &["state_set", "state_get", "state_incr", "state_delete", "state_all", "state_merge", "state_cas", "agents", "agent_stop"];

/// Familias OS-facing (las tablas de `synsema_stdlib::pure`) que NO son sumideros porque LEEN: entradas
/// (stdin, sockets, procesos, terminal, watches, bus) y consultas del estado del host. Se declaran aparte
/// para que el anti-rot pueda exigir que toda familia que hable con el SO esté clasificada a mano: o
/// sumidero, o lectura declarada acá. Todas están además en `LABEL_PURE_BUILTINS`.
pub const LABEL_OS_READ_BUILTINS: &[&str] = &[
    "pipe", "pipe_recv", "tcp_recv", "tcp_stats", "pipe_stats",
    "agents", "bus_recv", "bus_topics", "cron_list", "cron_status", "cwd", "proc_recv", "proc_select",
    "proc_stats", "proc_status", "read_line", "select", "self_path", "term_recv", "term_size", "term_stats",
    "watch_recv", "watch_stats", "ws_recv", "ws_select", "ws_select_all", "ws_stats", "ws_status",
];

/// la contracara EXPLÍCITA de
/// `LABEL_SINK_BUILTINS`: todo builtin del wiring nativo que NO tiene efecto fuera del intérprete.
/// Entre las dos listas (más `CORE_SINK_BUILTINS` y los `label_aware` del core) cubren EXACTAMENTE
/// Lo que el motor registra: el anti-rot `every_effectful_family_is_a_label_sink` lo cruza contra
/// `registered_builtin_names()`, así que un builtin NUEVO rompe el test hasta que alguien decida, a
/// mano, de qué lado está. Ése es exactamente el hueco por el que pasó `parallel_map`.
pub const LABEL_PURE_BUILTINS: &[&str] = &[
    // Entradas y consultas del HOST: leen (stdin, sockets, procesos, terminal, watches, bus, cron, cwd) o
    // describen el proceso. NO son sumideros: un dato no SALE por ellas; el host que quiera tratarlas como
    // FUENTES las etiqueta en su borde. El anti-rot las cruza con las tablas OS-facing de `pure.rs`: toda
    // familia que hable con el SO tiene que estar acá o en la lista de sumideros
    // `agents` (swarm-only, como `agent_stop`) sólo aparece en el wiring de serve/swarm: lo destapó
    // el anti-rot al extenderse a ese wiring (auditoría ronda 3, M3).
    "agents",
    // v0.6.42: leer de un TCP o de un pipe, y crear un pipe (memoria del proceso, nada sale).
    "pipe", "pipe_recv", "tcp_recv", "tcp_stats", "pipe_stats",
    "bus_recv", "bus_topics", "cron_list", "cron_status", "cwd", "proc_recv", "proc_select", "proc_stats",
    "proc_status", "read_line", "select", "self_path", "term_recv", "term_size", "term_stats", "watch_recv",
    "watch_stats", "ws_recv", "ws_select", "ws_select_all", "ws_stats", "ws_status",
    // Reloj, entropía y args del proceso: fuentes sin efecto de salida (`now`/`sleep` son además el canal de
    // TIEMPO que la spec declara NO cubierto)
    "arg", "args", "date_parts", "flush", "format_time", "now", "parse_time", "platform", "push_vapid_keys",
    "random", "random_bytes", "random_int", "sleep", "steps", "token",
    // Firma y custodia: escriben una entrada de AUDIT (nombre de la clave y ubicación, ambos públicos) pero el
    // material y el resultado se quedan DENTRO del programa — la firma de un dato privado sale privada por el
    // despacho genérico, y publicarla exige pasar por un sumidero o un `declassify`
    "algorand_mnemonic", "algorand_mnemonic_to_key", "ecdsa_p256_sign", "ed25519_pubkey", "ed25519_sign",
    "hd_derive", "http_sign", "keystore_export", "keystore_import", "mnemonic_from_entropy",
    "mnemonic_generate", "mnemonic_to_entropy", "mnemonic_to_seed", "rsa_sign_sha256", "schnorr_pubkey",
    "schnorr_sign", "secp256k1_pubkey", "secp256k1_recover", "secp256k1_sign", "wif_import",
    // Identidad atestada y verificación de documentos: leen lo que el propio proceso publica; `attestation_key`
    // Devuelve un secret SELLADO  que sólo consumen firma y ECDH con la clave propia
    "attestation_document", "attestation_key", "attestation_verify",
    // Estado declarado y observabilidad, sólo LECTURA (las escrituras — `remember`, `add_rule`,
    // `create_progress`, `start_step`, `complete_step`, `fail_step`, `state_*` — sí son sumideros)
    "check_rules", "get_rules", "judge_available", "judge_model", "judge_usage", "llm_available", "llm_usage",
    "memory_summary", "openapi_json",
    "progress_display", "progress_percent", "resume_point", "spend_total",
    // Orden superior: no hacen efecto por sí mismos, DESPACHAN código del programa (el intérprete empuja el PC
    // A los callbacks, y los sumideros que use el callee se comprueban ahí). `parallel_map` NO está acá: cruza
    // A otro intérprete, donde la etiqueta no llega
    "apply", "call", "call_tool", "chunk", "collect", "count_where", "every", "find_all", "find_first",
    "fold", "group_by", "reduce", "some", "sort_by", "transform", "where", "zip_with",
    // Plantillas y vocabulario de respuesta: construyen VALORES (el sumidero es la respuesta HTTP, en `serve.rs`)
    "binary", "chart", "chart_svg", "clear_cookie", "code", "content", "created", "heading", "html", "image",
    "link", "list", "not_found", "ok", "ordered_list", "page", "prose", "raw", "redirect", "render",
    "respond", "section", "set_cookie", "with_header",
    // Cómputo puro: texto, colecciones, números, matrices, estadística, fechas, formatos (json/csv/toml/xml),
    // Criptografía sin material propio (hashes, MAC, verificación, ZK, ruido determinista), encoders de
    // blockchain y helpers de test. Cero efecto fuera del intérprete
    "abi_decode", "abi_encode", "abi_selector", "abs", "acos", "acosh", "aes_gcm_decrypt", "aes_gcm_encrypt",
    "algo_address", "algorand_tx", "algorand_tx_encode", "append", "arange", "array", "as_secret", "asin",
    "asinh", "assert", "assert_eq", "assert_error", "assert_ne", "at", "atan", "atan2", "atanh", "basic", "bearer",
    "bech32_decode", "bech32_encode", "beta", "btc_address", "btc_address_decode", "btc_script", "btc_tx",
    "btc_tx_raw", "btc_txid", "bytes", "bytes_to_int", "captoken_allows", "captoken_attenuate",
    "canonical_json", "captoken_mint", "captoken_verify", "capture", "cbrt", "ceil", "clamp", "complex", "conj",
    "constant_time_eq", "contains", "cos", "cosh", "csv_encode", "csv_parse", "decimal", "decode", "degrees",
    "det", "dot", "ecdh_keypair", "ecdh_public", "ecdh_shared_secret", "ecdsa_p256_verify", "ed25519_verify", "eig",
    "eip191_digest", "eip712_digest", "ends_with", "enumerate", "erf", "erfc", "eth_address", "exp", "eye",
    "factorial", "fail", "flatten", "float", "floor", "fmt", "full", "gamma", "gaussian_noise", "gcd",
    "groth16_verify", "hash160", "histogram", "hkdf_sha256", "hmac_sha256", "http_signature_verify", "hypot",
    "identity", "imag", "index_of", "insert", "int_to_bytes", "int_to_bytes_le", "inv", "is_array", "is_bytes",
    "is_complex", "is_decimal", "is_finite", "is_infinite", "is_nan", "join", "json_decode", "json_encode",
    "json_for_script", "jwt_sign", "jwt_verify", "keccak256", "keys", "laplace_noise", "lcm", "length",
    "lgamma", "linspace", "ln", "log10", "log2", "log_base", "lower", "matches", "matmul", "max", "mean",
    "median", "min", "multipart_encode", "ndim", "norm", "number", "ones", "password_hash", "password_verify",
    "percentile", "pow", "product", "psbt_decode", "psbt_encode", "psbt_finalize", "radians", "raise",
    "range", "real", "replace_re", "replace_text", "reshape", "reverse", "rlp_decode", "rlp_encode", "round",
    "round_to", "rsa_verify_sha256", "schnorr_verify", "secp256k1_verify", "sha256", "sha512", "sha512_256",
    "shape", "sign", "sin", "sinh", "size", "slice", "solana_message", "solana_pda", "solana_tx", "solve",
    "spl_ata", "spl_transfer_checked_data", "spl_transfer_data", "split", "sqrt", "starts_with", "std",
    "strip_ansi", "sum", "svd", "tan", "tanh", "text", "to_list", "toml_encode", "toml_parse", "totp",
    "totp_verify", "trace", "transpose", "trim", "trunc", "tx_eip1559", "tx_eip1559_raw", "type_of", "unique",
    "upper", "values", "var", "verify_hmac", "webauthn_register", "webauthn_verify", "xml_parse", "zeros",
    "did_key_decode", "did_key_document", "did_key_encode", "document_sign", "document_verify",
    "receipt", "receipt_verify",
    // v0.6.29: entero exacto, `0x…` y predicados de tipo.
    "int", "hex", "is_integer", "is_text", "is_list", "is_map",
    // v0.6.29: mapas, orden, texto y regex con sus nombres nuevos; la MAC en bytes.
    "get", "remove", "merge", "items", "sort", "replace", "regex_find_all", "regex_capture",
    "regex_replace", "fold_text", "hmac",
    // v0.6.44: HTTP Basic como secret (y su variante con form-encoding de OAuth).
    "oauth_basic",
    // v0.6.44 (HB2): bits sobre enteros de 64 bits y XOR de bytes.
    "bit_and", "bit_or", "bit_xor", "bit_not", "shl", "shr", "xor_bytes",
    // v0.6.29: blockchain `<familia>_<acción>` (puros: construir, derivar, decodificar).
    "evm_address", "evm_signature", "evm_tx", "evm_tx_raw", "evm_tx_create", "evm_create_address",
    "evm_create2_address", "abi_event_topic", "abi_decode_log", "algorand_address", "algorand_tx_raw",
    "solana_tx_raw",
    // v0.6.29 (datos): tablas, faltantes, estadística, arrays, azar con semilla, fechas, JSONL,
    // linaje. Todos puros (el azar con semilla es determinista; las fechas no leen el reloj).
    "summarize", "count_by", "pivot", "count", "count_missing", "sum_of", "mean_of", "min_of", "max_of", "median_of",
    "first_of", "n_unique_of", "quantile_of", "is_missing", "fill_missing", "drop_missing", "fill_nan",
    "quantile", "concat", "stack", "argmin", "argmax", "cumsum", "diff", "cov", "corr", "lstsq",
    "polyfit", "polyval", "mode", "rng", "rng_spawn", "random_normal", "shuffle", "sample", "choice", "date",
    "datetime", "duration", "parse_date", "parse_datetime", "truncate", "add_months", "date_range",
    "timestamp", "to_timezone", "in_units", "add_days", "jsonl_encode", "jsonl_decode", "lineage", "parquet_read", "parquet_write",
];

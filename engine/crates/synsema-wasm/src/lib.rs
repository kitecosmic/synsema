//! synsema-wasm — el intérprete Synsema como artefacto WebAssembly (biblioteca).
//!
//! Una sola verdad del wiring PURO (`wire_pure`) para los dos artefactos wasm:
//! - el bin wasip1 de este crate (`main.rs`: CLI para wasmtime / TEEs / runners), y
//! - el cdylib `synsema-wasm-web` (`wasm32-unknown-unknown`: navegador, Node/Bun/Deno,
//!   Python vía wasmtime-py, Go vía wazero — ABI JSON + hooks del host).
//!
//! API embebible (sin tipos de Rust en la frontera final — la frontera JSON la arma
//! synsema-wasm-web sobre estas funciones):
//! - [`run`]     → salida de `print` + errores + audit de capabilities.
//! - [`test`]    → los bloques `test` del archivo.
//! - [`check`]   → parse + validaciones estáticas (declaración de memoria).
//! - [`handle`]  → `serve` en modo handler: un request → una respuesta (edge).
//! - [`version`].
//!
//! El perfil puro es el MISMO lenguaje en un entorno que sólo otorga lo que el host
//! presta (`hostcap::HostProvider`): red (`fetch`/`http_*`/RPC read-side) si el host
//! ofrece `http`; LLM real si ofrece `llm`; memoria persistente (`remember`/`recall`/
//! progress/rules) y `state_*` si ofrece `kv`. Lo que el host NO presta falla con la
//! verdad del entorno — nunca con "Undefined variable". El programa sigue teniendo
//! que declarar (`require net/llm/memory`) y el techo del embebedor (`ceiling`)
//! sigue mandando: ningún hook del host se llama sin pasar por `caps.require`.
//!
//! El wiring espeja el subconjunto puro de `wire_common_with_state` de
//! synsema-runtime/src/engine.rs (que no compila a wasm por sus módulos nativos);
//! si aquel cambia hooks o registraciones puras, esto se actualiza a mano.

pub mod handler;

use synsema_core::synlist::{list_values};
use synsema_core::types::SynMap;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use synsema_agents::builtins::{
    register_agent_builtins, register_serve_memory_builtins, register_serve_progress_builtins,
    register_shared_rules_builtins, MemoryGate,
};
use synsema_agents::memory::AgentMemory;
use synsema_agents::progress::ProgressManager;
use synsema_capabilities::model::{
    capability_type_from_name, validate_memory_name, CapSet, Capability, CapabilitySet, CapabilityType,
};
use synsema_capabilities::secure::register_secure_builtins;
use synsema_core::ast::{Node, NodeKind, Program};
use synsema_core::interpreter::{Control, Interpreter, RunResult, RuntimeError};
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{syn_bool, syn_list, syn_map, SynValue};
use synsema_stdlib::hostcap::{self, HostProvider};
use synsema_stdlib::json::{dumps_syn, json_to_syn};
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

pub use synsema_capabilities::model::build_ceiling;
pub use synsema_stdlib::hostcap::{HostHttpRequest, HostLlmResult, HttpResult};

pub(crate) fn rt_err(msg: &str) -> Control {
    Control::Error(RuntimeError::new(msg.to_string()))
}

/// Versión del artefacto: el tag del release (`SYNSEMA_VERSION`, lo setea release.yml)
/// o `v<crate>-dev` en un build desde fuente — misma regla que el binario nativo.
pub fn version() -> String {
    match option_env!("SYNSEMA_VERSION") {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => format!("v{}-dev", env!("CARGO_PKG_VERSION")),
    }
}

// =========================================================
// opciones + reportes (la API embebible)
// =========================================================

/// Cómo correr un programa. `env` reemplaza al `.env`/environ (un host sin FS ni
/// proceso lo pasa como mapa); `None` = `EnvStore::load_default()` (el bin wasip1 lee
/// `.env` por WASI). `ceiling` = techo del host (`--sandbox`/`--cap-set`, ver
/// [`parse_ceiling`]).
#[derive(Default)]
pub struct RunOptions {
    pub filename: String,
    pub env: Option<HashMap<String, String>>,
    pub ceiling: Option<Vec<Capability>>,
    /// El host NO tiene filesystem (navegador, Node sin WASI…): los builtins de archivos
    /// existen y lo dicen. `false` en el bin wasip1 (FS por WASI, `--dir`).
    pub no_fs: bool,
    /// Etiquetas de flujo de información encendidas (`private`/`declassify`).
    /// Apagadas por defecto: la variante `Private` no existe en runtime y el coste es cero.
    /// Un host que fija fuentes y sumideros (el adaptador de un enclave) las enciende.
    pub labels: bool,
    /// Nombre de una variable GLOBAL cuyo valor final se devuelve en
    /// `Report.result` CON sus etiquetas intactas. Es el canal por el que un host aplica sus
    /// sumideros: en vez de leer un `print(json_encode(x))` (que redactaría un privado), recibe
    /// El valor estructurado y decide, por campo, quién puede verlo (`labels::check_flow`).
    pub result: Option<String>,
    /// La ENTRADA del host por API: `(variable global, valor JSON)`
    /// Ligada ANTES de ejecutar el programa. Reemplaza al `let x be json_decode("…")` inyectado
    /// En el fuente: sin escape de literales ni superficie de inyección, y las fuentes se
    /// etiquetan desde Rust (`sources`), no con un `private(...)` que una `task private` del
    /// programa pudiera sombrear.
    pub input: Option<(String, serde_json::Value)>,
    /// FUENTES: `(clave del mapa de entrada, principales)`. Cada clave listada
    /// que exista y no sea `nothing` llega al programa como `private(valor, principales)`.
    /// Exige `labels` (sin etiquetas no hay fuentes que marcar: error, no silencio).
    pub sources: Vec<(String, Vec<String>)>,
    /// v0.6.45 (D2) — tope de pasos del intérprete (`steps()`); al pasarlo, la corrida termina con
    /// un error claro, no con un trap. Sólo en wasm32 (en el binario nativo se ignora).
    pub max_steps: Option<u64>,
    /// v0.6.45 (D2) — tope de la memoria lineal del módulo, en MB. Sólo en wasm32.
    pub max_memory_mb: Option<u64>,
    /// v0.6.46 (E3b) — módulos de confianza del embebedor `(nombre, fuente)`: el programa los
    /// importa con `use "trusted:nombre"`, y sus tasks exportadas corren con sus `require` ∩
    /// `trusted_ceiling`, no con lo del programa.
    pub trusted: Vec<(String, String)>,
    /// v0.6.50 (D): los templates de cada tool (`trusted: {nombre: {source, templates}}`).
    pub trusted_templates: Vec<(String, Vec<(String, String)>)>,
    /// v0.6.46 (E3b) — el techo de los módulos de confianza (la gramática de `ceiling`).
    pub trusted_ceiling: Option<Vec<Capability>>,
    /// v0.6.46 (E6) — la pública X25519 del auditor que designa el host: con ella, `Report.receipt`
    /// trae el recibo sellado de la corrida (lo de una rama privada va cifrado para el auditor, en
    /// un sobre de tamaño fijo).
    pub auditor: Option<[u8; 32]>,
    /// v0.6.46 (E6) — el tamaño del texto plano del sobre (por defecto 64 KiB).
    pub sealed_bytes: Option<usize>,
    /// v0.6.47 (T1) — el diagnóstico entero de un corte de etiquetas va al programa (en `errors` y
    /// en el reporte de tests), como `synsema run` sin techo. Lo prende sólo quien escribió el
    /// programa (el bin wasip1 sin techo); un embebedor lo deja apagado y lee `operator_detail`.
    pub labels_detail_to_program: bool,
}

impl RunOptions {
    pub fn new(filename: &str) -> Self {
        RunOptions {
            filename: filename.to_string(),
            env: None,
            ceiling: None,
            no_fs: false,
            labels: false,
            result: None,
            input: None,
            sources: Vec::new(),
            max_steps: None,
            max_memory_mb: None,
            trusted: Vec::new(),
            trusted_templates: Vec::new(),
            trusted_ceiling: None,
            auditor: None,
            sealed_bytes: None,
            labels_detail_to_program: false,
        }
    }
}

/// `"sandbox"` → techo [stdout, time]; otro texto → la lista de `--cap-set`
/// (`"stdout,secret=ETH_*"`); vacío → sin techo.
pub fn parse_ceiling(spec: &str) -> Result<Option<Vec<Capability>>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }
    if spec == "sandbox" {
        return build_ceiling(true, None);
    }
    build_ceiling(false, Some(spec))
}

/// Una entrada del audit log de capabilities: lo que el programa pidió y si se le
/// concedió — el embebedor ve qué hizo el programa con sus capabilities. Es el MISMO
/// tipo que exporta el binario nativo (`--audit json`, `run --format json`).
pub use synsema_capabilities::model::{export_audit, AuditEntry};

pub struct Report {
    pub ok: bool,
    pub output: Vec<String>,
    pub errors: Vec<String>,
    pub audit: Vec<AuditEntry>,
    /// Tokens LLM consumidos vía el hook `llm` del host (lo que `llm_usage()` ve).
    pub llm_tokens: u64,
    /// v0.6.20 — pasos del intérprete (nodos ejecutados): determinista, el "fuel" de un
    /// host que lo exija y una medida de trabajo para budgets y tests.
    ///
    /// ⚠️ T5 (ronda 5) — **no publicarlo si `private_seen`**. Es un paso por nodo del AST, o sea
    /// lineal en lo que el programa recorrió: después de un bucle cuya condición dependió de un
    /// secreto, este número ES el secreto con una multiplicación y una suma encima (medido:
    /// reconstruido exacto en una línea). El host lo recibe para medir costo, no para exponerlo;
    /// `private_seen` viaja al lado justamente para decidirlo. El adaptador de Vela no lo loguea
    /// ni lo manda a la cadena, y `synsema run --format json` lo reporta `null` en ese caso.
    pub steps: u64,
    /// El valor final de `RunOptions.result` (si se pidió, la variable quedó
    /// ligada y la corrida terminó bien) como JSON que CONSERVA las etiquetas (ver
    /// [`labelled_json`]): el host aplica sus sumideros campo a campo. `Send` a propósito (el
    /// bin nativo corre el programa en un hilo con stack grande).
    pub result: Option<serde_json::Value>,
    /// Cada `declassify` ejecutado (motivo, de qué etiqueta a cuál, dónde):
    /// El host lo registra en su log; es la revisión que un auditor hace.
    pub declassify: Vec<DeclassifyRecord>,
    /// La corrida desenvolvió algún valor privado: el host debe
    /// tratar los mensajes de error como sensibles (redactarlos fuera del enclave).
    pub private_seen: bool,
    /// v0.6.42 — el código que pidió `exit(code)`, si lo llamó (`ok` = código 0, sin errores).
    pub exit_code: Option<i32>,
    /// v0.6.46 (E6) — el recibo sellado, si el host puso un auditor (`RunOptions.auditor`). El host lo
    /// entrega ANTES que la salida.
    pub receipt: Option<serde_json::Value>,
    /// v0.6.47 (T1) — el diagnóstico entero de un corte de etiquetas (sitio, remedio, ubicación), para
    /// el OPERADOR. En `errors` el programa ve un texto fijo; esto no va nunca ahí ni al log del
    /// programa. Depende del dato privado: el host no se lo devuelve a un modelo, y bajo el guest no
    /// sale del enclave.
    pub operator_detail: Option<String>,
}

/// Un `declassify` ejecutado, en forma plana (`Send`, serializable).
#[derive(Clone, Debug)]
pub struct DeclassifyRecord {
    pub reason: String,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub line: usize,
    pub column: usize,
}

impl DeclassifyRecord {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"reason": self.reason, "from": self.from, "to": self.to, "line": self.line, "column": self.column})
    }
}

/// Un valor Synsema como JSON que CONSERVA las etiquetas: un `Private` sale
/// como `{"$private": ["a", "b"], "value": …}` (y su interior sin repetir la etiqueta), los
/// bytes como `{"$bytes": "<base64>"}`, un `secret` redactado (`"secret(NAME)"`), y lo demás
/// con la MISMA forma que `json_encode` (enteros como número, big/decimal como número crudo:
/// `syn_to_json` de la stdlib, para que un host que antes leía `print(json_encode(x))` vea lo
/// mismo). toda clave de programa que empiece con `$` se ESCAPA anteponiendo otro
/// `$` (`"$bytes"` del usuario → `"$$bytes"`), así los marcadores nunca colisionan con datos que
/// controle un tercero; el host revierte el escape al quitar los marcadores.
pub fn labelled_json(v: &SynValue) -> serde_json::Value {
    use serde_json::{json, Value};
    match v {
        SynValue::Private(p) => json!({
            "$private": p.label.iter().map(|s| Value::String(s.to_string())).collect::<Vec<_>>(),
            "value": labelled_json(&p.value),
        }),
        SynValue::Nothing => Value::Null,
        SynValue::Bool(b) => Value::Bool(*b),
        SynValue::Text(t) => Value::String(t.to_string()),
        SynValue::Bytes(b) => json!({"$bytes": base64_std(b)}),
        SynValue::List(l) => Value::Array(list_values(&l).iter().map(labelled_json).collect()),
        SynValue::Map(m) => Value::Object(m.borrow().iter().map(|(k, v)| (escape_marker_key(k), labelled_json(v))).collect()),
        // Redactado por `Display`: un secret jamás cruza esta frontera en claro.
        SynValue::Secret(_) => Value::String(v.to_string()),
        // Números (int/float/big/decimal), complejos, arrays y los valores del servidor
        // (`ok(...)`, `html(...)`, nodos de contenido): exactamente como `json_encode`. Esa ruta
        // No pasa por el brazo `Map` de arriba, así que el escape de claves `$` se aplica sobre
        // El JSON ya producido — si no, un `ok({"$private": ["x"], "value": …})` armado por el
        // sender vuelve a ser un marcador falso del lado del host.
        other => {
            let text = synsema_stdlib::json::dumps_syn(other);
            let parsed = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(other.to_string()));
            escape_marker_keys_deep(parsed)
        }
    }
}

/// Aplica [`escape_marker_key`] a TODAS las claves de un JSON ya construido (la ruta que no pasa
/// por el brazo `Map` de [`labelled_json`]).
fn escape_marker_keys_deep(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().map(|(k, val)| (escape_marker_key(&k), escape_marker_keys_deep(val))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(escape_marker_keys_deep).collect()),
        other => other,
    }
}

/// `$x` → `$$x` (los marcadores `$private`/`$bytes` son sólo nuestros). Idempotente al revés
/// con [`unescape_marker_key`].
pub fn escape_marker_key(k: &str) -> String {
    if k.starts_with('$') {
        format!("${}", k)
    } else {
        k.to_string()
    }
}

/// Revierte [`escape_marker_key`]: `$$x` → `$x`. Una clave `$private`/`$bytes` sin escapar es
/// Un marcador y no pasa por acá.
pub fn unescape_marker_key(k: &str) -> String {
    match k.strip_prefix("$$") {
        Some(rest) => format!("${}", rest),
        None => k.to_string(),
    }
}

/// Base64 estándar con padding (para `{"$bytes": …}`); sin dependencia nueva.
fn base64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub struct TestReport {
    pub passed: usize,
    pub failed: usize,
    pub lines: Vec<String>,
    pub audit: Vec<AuditEntry>,
}

pub struct CheckReport {
    pub ok: bool,
    pub errors: Vec<String>,
}

// =========================================================
// estado compartido del wiring (memoria declarada, tokens LLM)
// =========================================================

thread_local! {
    /// Tokens LLM acumulados por el hook `llm` del host (una cuenta por instancia
    /// wasm, como `llm_tokens_total` del proceso nativo).
    static LLM_TOKENS: RefCell<u64> = const { RefCell::new(0) };
}

/// Tokens LLM acumulados en esta instancia (lo que devuelve `llm_usage()`).
pub fn llm_tokens_total() -> u64 {
    LLM_TOKENS.with(|t| *t.borrow())
}

/// Escanea las declaraciones `require memory("<nombre>")` del TOP-LEVEL (mismo
/// criterio que `declared_memory_name` del runtime: sólo literales, una sola
/// identidad, G-6). `Ok(None)` = sin memoria declarada.
pub fn declared_memory_name(statements: &[Node]) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
    for stmt in statements {
        if let NodeKind::RequireStatement { capability, scope, .. } = &stmt.kind {
            if capability != "memory" {
                continue;
            }
            if let Some(scope_node) = scope {
                if let NodeKind::TextLiteral { value } = &scope_node.kind {
                    validate_memory_name(value)?;
                    match &found {
                        Some(prev) if prev != value => {
                            return Err(format!(
                                "Multiple memory declarations: require memory(\"{}\") and require memory(\"{}\"). A program has exactly ONE declared memory (the declared name IS its identity) — keep one declaration",
                                prev, value
                            ));
                        }
                        _ => found = Some(value.clone()),
                    }
                }
            }
        }
    }
    Ok(found)
}

/// Nombre de memoria sugerido en el error sin declaración (stem del archivo).
fn suggested_memory_name(filename: &str) -> String {
    let stem = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename)
        .trim_end_matches(".syn")
        .trim_end_matches(".fsyn");
    let cleaned: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    if cleaned.is_empty() || filename == "<stdin>" {
        "my-agent".to_string()
    } else {
        cleaned
    }
}

/// Namespace del KV del host para una memoria declarada: `memory:<nombre>` — la
/// identidad sigue siendo el NOMBRE DECLARADO (doctrina DB-M1), en cualquier host.
pub fn memory_namespace(name: &str) -> String {
    format!("memory:{}", name)
}

/// Contexto de la memoria DECLARADA respaldada por el KV del host.
pub struct HostMemoryCtx {
    pub name: String,
    pub memory: Arc<Mutex<AgentMemory>>,
    pub progress: Arc<Mutex<ProgressManager>>,
}

/// Abre (carga) la memoria declarada desde el KV del host. `Ok(None)` si el host no ofrece `kv`
/// (entonces la familia falla con el gate). v0.6.46: `Err` si una lectura falló: la memoria no se
/// abre (cargarla vacía hacía que la próxima escritura pisara la guardada) y el gate lo dice.
fn open_host_memory(name: &str, host: Option<&Rc<dyn HostProvider>>) -> Result<Option<HostMemoryCtx>, String> {
    let Some(host) = host else { return Ok(None) };
    if !host.offers("kv") {
        return Ok(None);
    }
    let ns = memory_namespace(name);
    let mut mem = AgentMemory::new();
    mem.backend = Some("host-kv".to_string());
    if let Some(Some(json)) = host.kv_get(&ns, "memory").transpose().map_err(|e| format!("the host's kv.get failed: {}", e))? {
        mem.try_load_json(&json).map_err(|e| format!("the stored memory is not readable ({})", e))?;
    }
    let mut prog = ProgressManager::new();
    if let Some(Some(json)) = host.kv_get(&ns, "progress").transpose().map_err(|e| format!("the host's kv.get failed: {}", e))? {
        prog.try_load_json(&json).map_err(|e| format!("the stored progress is not readable ({})", e))?;
    }
    Ok(Some(HostMemoryCtx {
        name: name.to_string(),
        memory: Arc::new(Mutex::new(mem)),
        progress: Arc::new(Mutex::new(prog)),
    }))
}

fn kv_write(ns: &str, key: &str, value: &str) {
    if let Some(p) = hostcap::provider() {
        if let Some(Err(e)) = p.kv_set(ns, key, value) {
            hostcap::log(&format!("synsema: warning: host kv write failed ({}/{}): {}", ns, key, e));
        }
    }
}

// =========================================================
// wiring puro
// =========================================================

/// Lo que `wire_pure` necesita además del intérprete y el CapabilitySet.
pub struct WireCtx<'a> {
    pub env: Rc<EnvStore>,
    /// Statements del programa (para la declaración de memoria).
    pub statements: &'a [Node],
    pub filename: &'a str,
    pub no_fs: bool,
}

/// Cablea el perfil puro: builtins puros de la stdlib, hooks de capabilities
/// (grant/sandbox/tool-scope/llm), parallel_map secuencial, y — según lo que el host
/// ofrezca — red, LLM, memoria y `state_*`. Idempotente por intérprete.
pub fn wire_pure(interp: &mut Interpreter, caps: &Rc<RefCell<CapabilitySet>>, ctx: &WireCtx<'_>) {
    let host = hostcap::provider();

    // No-secure (paridad con `synsema run`): stdout/time/llm auto-concedidas; el
    // resto lo conceden los `require` del programa vía el grant hook de abajo.
    caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Stdout, None));
    caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Time, None));
    caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Llm, None));
    // `judge` (System One) se concede ambiente como en el nativo — la sonda de paridad compara
    // el audit nativo ↔ wasm bajo un ceiling y la denegación tiene que aparecer en los dos.
    // En el guest no hay red ni provider: un bloque `judge` degrada siempre a `available: false`.
    caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Judge, None));
    // v0.6.46 (E3): `declassify` como capability, con el mismo helper que el nativo (paridad).
    synsema_stdlib::captoken::install_declassify_hook(interp, caps.clone());
    // v0.6.46 (E5): datos privados hacia el modelo, con el mismo helper que el nativo. En wasm el
    // modelo es el del host que embebe (o ninguno): `llm=P@embedder` en el techo.
    synsema_stdlib::captoken::install_llm_data_hook(interp, caps.clone(), Rc::new(|_| "embedder".to_string()));

    register_secure_builtins(interp, caps.clone());
    // Gate de stdout bajo techo (paridad con el nativo): `ceiling` sin `stdout` deniega
    // el primer `print` en vez de imprimir igual.
    {
        let caps_out = caps.clone();
        interp.set_stdout_hook(Rc::new(move || {
            let mut cs = caps_out.borrow_mut();
            if cs.ceiling.is_none() {
                return Ok(());
            }
            cs.require(&Capability::new(CapabilityType::Stdout, None), "print()").map_err(|v| v.message)
        }));
    }
    {
        let caps_tpl = caps.clone();
        interp.set_template_read_hook(Rc::new(move |raw: &str| {
            let path = synsema_capabilities::model::normalize_path(raw);
            caps_tpl
                .borrow_mut()
                .require(&Capability::new(CapabilityType::FileRead, Some(path)), "render()")
                .map_err(|v| v.into_error())
        }));
    }
    if ctx.no_fs {
        synsema_stdlib::pure::register_no_fs_stubs(interp, synsema_stdlib::pure::WEB_NO_FS_HINT);
    }
    register_secret_builtins(interp, caps.clone(), ctx.env.clone());
    synsema_stdlib::hashing::register_hash_builtins(interp);
    synsema_stdlib::bits::register_bit_builtins(interp);
    synsema_stdlib::encoding::register_encoding_builtins(interp);
    synsema_stdlib::headers::register_header_builtins(interp);
    synsema_stdlib::qr::register_qr_builtins(interp);
    synsema_stdlib::html::register_html_builtins(interp);
    // Groth16_verify (puro; arkworks no_std sin parallel/asm). Medido en wasip1 --profile
    // wasm: 7 144 498 → 7 288 665 bytes (+141 KB; el spec presupuestaba +1–1,5 MB).
    synsema_stdlib::zk::register_zk_builtins(interp);
    // Verificar attestation (nitro/mock; puro, `now` explícito) y ruido
    // determinista para privacidad de salida. Ambos puros: entran al guest y al bin wasip1.
    synsema_stdlib::attestation::register_attestation_builtins(interp);
    synsema_stdlib::privacy::register_privacy_builtins(interp);
    synsema_stdlib::json::register_json_builtins(interp);
    // v0.6.20 — parsers y criptografía genérica, puros: el mismo camino que el nativo.
    synsema_stdlib::xml::register_xml_builtins(interp);
    synsema_stdlib::toml_fmt::register_toml_builtins(interp);
    synsema_stdlib::crypto::register_crypto_builtins(interp, caps.clone());
    synsema_stdlib::webauth::register_webauth_builtins(interp, caps.clone());
    synsema_stdlib::webauthn::register_webauthn_builtins(interp);
    synsema_stdlib::canonical::register_canonical_builtins(interp);
    synsema_stdlib::tools::register_tool_builtins(interp);
    synsema_stdlib::didkey::register_didkey_builtins(interp);
    synsema_stdlib::integrity::register_integrity_builtins(interp, caps.clone());
    synsema_stdlib::receipt::register_receipt_builtins(interp, caps.clone());
    synsema_stdlib::httpsig::register_httpsig_builtins(interp, caps.clone());
    synsema_stdlib::captoken::register_captoken_builtins(interp, caps.clone());
    synsema_stdlib::oidc::register_oidc_builtins(interp, caps.clone());
    // Web Push: cifrado/VAPID puros; el POST al push service necesita sockets → en wasm
    // `push_send` falla con el error claro del build sin `native` (como oidc_verify).
    synsema_stdlib::webpush::register_webpush_builtins(interp, caps.clone());
    // `platform()` existe también acá, con la verdad del host: `{os: "wasm", arch: "wasm32"}`.
    synsema_stdlib::platform::register_platform_builtin(interp, "wasm", "wasm32");
    synsema_stdlib::blockchain::register_blockchain_builtins(interp, caps.clone());
    synsema_stdlib::spend::register_spend_builtins(interp, caps.clone());
    // Respuesta + vocabulario content() (respond.rs, puro): ok/created/…/page/heading/
    // prose/content — registra también charts y raster, el MISMO camino que el nativo.
    synsema_stdlib::respond::register_serve_builtins(interp);
    // Red (F3): los seis builtins cliente, gateados por `net(host)` ANTES del transporte;
    // el transporte es el `http` del host o el stub "sin transporte" (http_stub.rs).
    synsema_stdlib::http::register_http_builtins(interp, caps.clone());
    // Lo que este perfil NO compila (WebSocket, DB, scheduler): los nombres EXISTEN y
    // fallan con la verdad del entorno. "Undefined variable: 'sql'" haría creer que el
    // nombre no existe o está mal escrito; el error debe nombrar el problema y el fix.
    synsema_stdlib::pure::register_os_stubs(interp, synsema_stdlib::pure::WASM_HINT);
    synsema_stdlib::pure::register_no_threads_stubs(interp, synsema_stdlib::pure::WASM_HINT);

    // sleep(): el de secure.rs usa std::thread::sleep, que en un host sin SO panica;
    // acá va por el reloj del motor (pausa del host o no-op). Misma capability `time`.
    {
        let caps_sleep = caps.clone();
        interp.register_builtin(
            "sleep",
            1,
            Rc::new(move |_i, args, _loc| {
                caps_sleep
                    .borrow_mut()
                    .require(&Capability::new(CapabilityType::Time, None), "sleep()")
                    .map_err(|v| Control::Error(v.into_error()))?;
                let secs = match args.first() {
                    Some(SynValue::Number(n)) => n.to_f64(),
                    _ => 0.0,
                };
                synsema_core::clock::sleep_secs(secs.clamp(0.0, 3600.0));
                Ok(SynValue::Nothing)
            }),
        );
    }

    // chunk + parallel_map: en wasm no hay threads — chunk es puro (misma validación
    // que runtime/parallel.rs) y parallel_map corre SECUENCIAL con la misma semántica
    // observable (resultados en orden de entrada, fail-fast en el primer error, como
    // el `apply` secuencial). `limit` se acepta y se ignora: es un knob de
    // paralelismo, no de semántica.
    interp.register_builtin(
        "chunk",
        2,
        Rc::new(|_i, args, _loc| {
            let list = match args.first() {
                Some(SynValue::List(l)) => l.borrow().to_vec(),
                _ => return Err(rt_err("chunk: first argument must be a list")),
            };
            let size = match args.get(1) {
                Some(SynValue::Number(n)) => n.to_i64_trunc().unwrap_or(0),
                _ => return Err(rt_err("chunk: size must be a number")),
            };
            if size <= 0 {
                return Err(rt_err("chunk size must be positive"));
            }
            let size = size as usize;
            let chunks: Vec<SynValue> =
                list.chunks(size).map(|c| syn_list(c.to_vec())).collect();
            Ok(syn_list(chunks))
        }),
    );
    interp.register_builtin(
        "parallel_map",
        -1,
        Rc::new(|i, args, _loc| {
            let task = match args.first() {
                Some(t @ (SynValue::Task(_) | SynValue::Builtin(_))) => t.clone(),
                _ => return Err(rt_err("parallel_map: first argument must be a task")),
            };
            let list = match args.get(1) {
                Some(SynValue::List(l)) => l.borrow().to_vec(),
                _ => return Err(rt_err("parallel_map: second argument must be a list")),
            };
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                out.push(i.call_task(task.clone(), vec![item])?);
            }
            Ok(syn_list(out))
        }),
    );

    // Familia de estado persistente (F4). Tres casos, todos con la verdad del entorno:
    //  - sin `require memory("x")`: error de capability + la sugerencia (como nativo);
    //  - declarada pero el host no ofrece `kv`: error que lo dice;
    //  - declarada y el host ofrece `kv`: stores compartidos cargados del KV y
    //    persistidos on-write (misma maquinaria que run/serve nativo, G-9), gateados por
    //    `memory("x")` contra el CapabilitySet VIVO (sandbox/tool-scope/techo).
    let declared = match declared_memory_name(ctx.statements) {
        Ok(d) => d,
        Err(e) => {
            hostcap::log(&format!("synsema: warning: {}", e));
            None
        }
    };
    let suggest = suggested_memory_name(ctx.filename);
    let opened = declared.as_ref().map(|n| open_host_memory(n, host.as_ref()));
    let load_err: Option<String> = match &opened {
        Some(Err(e)) => Some(e.clone()),
        _ => None,
    };
    let gate: MemoryGate = match &declared {
        None => Rc::new(move || {
            Err(RuntimeError::new(format!(
                "Capability not granted: memory. Persistent agent state (remember/recall, rules, progress) requires a declared memory — the declared name identifies its store. Add: require memory(\"{}\") at the top of the program",
                suggest
            )))
        }),
        Some(name) => {
            let caps_m = caps.clone();
            let name = name.clone();
            let has_kv = host.as_ref().is_some_and(|h| h.offers("kv"));
            Rc::new(move || {
                caps_m
                    .borrow_mut()
                    .require(&Capability::new(CapabilityType::Memory, Some(name.clone())), "memory builtin")
                    .map_err(|v| v.into_error())?;
                if !has_kv {
                    return Err(RuntimeError::new(format!(
                        "memory \"{}\" is declared but this host provides no durable storage (wasm profile) — the embedder can offer it through the `kv` host hook, or run the program with the native `synsema` binary",
                        name
                    )));
                }
                if let Some(e) = &load_err {
                    return Err(RuntimeError::new(format!(
                        "memory \"{}\" could not be loaded ({}); nothing was loaded, so nothing is written over it",
                        name, e
                    )));
                }
                Ok(())
            })
        }
    };
    register_agent_builtins(
        interp,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(AgentMemory::new())),
        gate.clone(),
    );
    if let Some(name) = &declared {
        if let Some(Ok(Some(mctx))) = opened {
            let ns = memory_namespace(name);
            let ns_m = ns.clone();
            let on_write_mem: Arc<dyn Fn(&AgentMemory) + Send + Sync> =
                Arc::new(move |m: &AgentMemory| kv_write(&ns_m, "memory", &m.to_json()));
            let ns_p = ns.clone();
            let on_write_prog: Arc<dyn Fn(&ProgressManager) + Send + Sync> =
                Arc::new(move |p: &ProgressManager| kv_write(&ns_p, "progress", &p.to_json()));
            register_serve_memory_builtins(interp, mctx.memory.clone(), on_write_mem.clone(), gate.clone());
            register_serve_progress_builtins(interp, mctx.progress.clone(), on_write_prog, gate.clone());
            register_shared_rules_builtins(interp, mctx.memory.clone(), on_write_mem, gate.clone());
        }
    }

    // state_* (el estado compartido de serve): sobre el KV del host (namespace `state`)
    // si lo ofrece — durable entre requests/invocaciones del handler —; si no, un mapa
    // en memoria de ESTE intérprete (vive lo que la instancia).
    register_state_builtins(interp, host.as_ref().is_some_and(|h| h.offers("kv")));

    // LLM (F3): si el host ofrece `llm`, las ops reason/decide/analyze/generate van al
    // host (llm_available() = true; llm_usage() suma los tokens que el host reporte).
    // Sin él: placeholders offline del core, como hasta ahora. `require llm` no cambia.
    if host.as_ref().is_some_and(|h| h.offers("llm")) {
        interp.set_llm_callback(Rc::new(|op: &str, prompt: &str, principals: &[Rc<str>]| {
            let principals: Vec<String> = principals.iter().map(|p| p.to_string()).collect();
            match hostcap::provider().and_then(|p| p.llm(op, prompt, &principals)) {
                Some(Ok(r)) => {
                    LLM_TOKENS.with(|t| *t.borrow_mut() += r.tokens);
                    Ok(r.content)
                }
                Some(Err(e)) => Err(e),
                None => Ok(format!("[llm: the host returned no answer for {}]", op)),
            }
        }));
        interp.set_llm_usage_callback(Rc::new(llm_tokens_total));
    }

    // render real (sobrescribe el placeholder de core) — mismo snippet que engine.rs.
    interp.register_builtin(
        "render",
        -1,
        Rc::new(|i, args, _loc| {
            let path = args.first().map(|v| v.to_string()).unwrap_or_default();
            // El gate `file.read` lo decide `render_template` (paridad con el nativo).
            let html = synsema_core::templates::render_template(i, &path, args.get(1))?;
            Ok(synsema_core::templates::make_raw(html, "text/html; charset=utf-8", 200))
        }),
    );

    // Grant hook: `require X(scope)` concede — con los mismos avisos que el runtime
    // para los grants sin scope que amplían poder (reveal/sign/spend/wallet). Los
    // avisos van al log del host (stderr en wasip1).
    let c = caps.clone();
    interp.set_grant_hook(Rc::new(move |name, scope| {
        if let Some(ty) = capability_type_from_name(name) {
            if ty == CapabilityType::Reveal && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require reveal` permits revealing ANY secret; \
                     scope it with `require reveal(\"NAME\")` (the name/label of the secret)",
                );
            }
            if ty == CapabilityType::Sign && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require sign` permits signing with ANY key; \
                     scope it with `require sign(\"KEY_NAME\")` (the name of the key's secret)",
                );
            }
            if ty == CapabilityType::Spend && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require spend` permits spending in ANY unit; \
                     scope it with `require spend(\"USD\")` (the unit being spent)",
                );
            }
            if ty == CapabilityType::Wallet && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require wallet` permits creating custody from ANY secret; \
                     scope it with `require wallet(\"NAME\")` (the source secret's name, or the new \
                     secret's label when generating)",
                );
            }
            // v0.6.46 (E3): ídem para `declassify` (publicar lo privado de cualquier principal).
            if ty == CapabilityType::Declassify && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require declassify` permits publishing data private to ANY principal; \
                     scope it with `require declassify(\"principal\")` (the principal the call removes)",
                );
            }
            c.borrow_mut().grant(Capability::new(ty, scope.map(|s| s.to_string())));
        }
    }));

    // Gate de las ops LLM (reason/decide/analyze/generate): auto-concedida arriba,
    // pero el chequeo queda auditado en el mismo CapabilitySet (paridad runtime).
    let caps_llm = caps.clone();
    interp.set_llm_cap_hook(Rc::new(move || {
        caps_llm
            .borrow_mut()
            .require(&Capability::new(CapabilityType::Llm, None), "llm operation")
            .map_err(|v| v.into_error())
    }));
    // v0.6.46 (E5): el gate de `judge` también en wasm (antes no había: `judge` pasaba con o sin
    // la capability, aunque el techo no la diera). Mismo chequeo que el nativo.
    let caps_judge = caps.clone();
    interp.set_judge_cap_hook(Rc::new(move || {
        caps_judge
            .borrow_mut()
            .require(&Capability::new(CapabilityType::Judge, None), "judge block")
            .map_err(|v| v.into_error())
    }));
    // `sandbox under <caps>` (T1): techo delegado por bloque — mismo helper que el runtime.
    synsema_stdlib::captoken::install_ceiling_hook(interp, caps.clone());

    // Aislamiento de `sandbox`: guarda y VACÍA el CapabilitySet al entrar; restaura
    // al salir (stack para anidados) — idéntico al runtime.
    #[allow(clippy::type_complexity)]
    let saved: Rc<RefCell<Vec<(CapSet, CapSet, Option<Rc<RefCell<CapabilitySet>>>)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let caps_sb = caps.clone();
    interp.set_sandbox_hook(Rc::new(move |entering| {
        let mut cs = caps_sb.borrow_mut();
        if entering {
            let g = std::mem::take(&mut cs.granted);
            let d = std::mem::take(&mut cs.denied);
            let p = cs.parent.take();
            saved.borrow_mut().push((g, d, p));
            cs.sandbox_depth += 1;
        } else if let Some((g, d, p)) = saved.borrow_mut().pop() {
            cs.granted = g;
            cs.denied = d;
            cs.parent = p;
            cs.sandbox_depth -= 1;
        }
    }));

    // Aislamiento por-tool (least-privilege): la tool corre con sus caps declaradas
    // ∩ las del agente, sin heredar el padre — idéntico al runtime.
    #[allow(clippy::type_complexity)]
    let saved_tool: Rc<RefCell<Vec<(CapSet, CapSet, Option<Rc<RefCell<CapabilitySet>>>)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let caps_tool = caps.clone();
    interp.set_tool_scope_hook(Rc::new(move |entering, declared: &[(String, Option<String>)]| {
        let mut cs = caps_tool.borrow_mut();
        if entering {
            let mut allowed: CapSet = CapSet::new();
            for (name, scope) in declared {
                if let Some(ty) = capability_type_from_name(name) {
                    let cap = Capability::new(ty, scope.clone());
                    if cs.check(&cap, "tool-scope") {
                        allowed.insert(cap);
                    }
                }
            }
            let g = std::mem::replace(&mut cs.granted, allowed);
            let d = std::mem::take(&mut cs.denied);
            let p = cs.parent.take();
            saved_tool.borrow_mut().push((g, d, p));
        } else if let Some((g, d, p)) = saved_tool.borrow_mut().pop() {
            cs.granted = g;
            cs.denied = d;
            cs.parent = p;
        }
    }));
}

/// `state_set/get/incr/delete/all` (paridad con serve.rs). Con `host_kv`, cada valor
/// vive en el KV del host bajo el namespace `state` (JSON); sin él, en un mapa de
/// este intérprete.
fn register_state_builtins(interp: &Interpreter, host_kv: bool) {
    const NS: &str = "state";
    let local: synsema_core::types::MapRef = SynMap::new().into_ref();

    fn load(host_kv: bool, local: &synsema_core::types::MapRef, key: &str, who: &str) -> Result<Option<SynValue>, Control> {
        if host_kv {
            let raw = match hostcap::provider() {
                Some(p) => raw_of(&p, key, who)?,
                None => None,
            };
            // v0.6.46 (ronda 2 de cf1, R2-B3): un valor guardado que no es JSON no es "no está": se
            // pisaba (`state_incr` sobre un texto suelto daba 1).
            match raw {
                None => Ok(None),
                Some(_) => value_of(&raw, key, who).map(Some),
            }
        } else {
            Ok(local.borrow().get(key).cloned())
        }
    }
    fn store(host_kv: bool, local: &synsema_core::types::MapRef, key: &str, v: &SynValue) {
        if host_kv {
            kv_write(NS, key, &dumps_syn(v));
        } else {
            local.borrow_mut().insert(key.to_string(), v.clone());
        }
    }
    fn key_arg(args: &[SynValue], who: &str) -> Result<String, Control> {
        match args.first() {
            Some(v) => Ok(v.to_string()),
            None => Err(rt_err(&format!("{}: missing key", who))),
        }
    }

    {
        let l = local.clone();
        interp.register_builtin("state_set", 2, Rc::new(move |_i, args, _l| {
            let key = key_arg(args, "state_set")?;
            let val = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            store(host_kv, &l, &key, &val);
            Ok(val)
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_get", -1, Rc::new(move |_i, args, _l| {
            let key = key_arg(args, "state_get")?;
            Ok(load(host_kv, &l, &key, "state_get")?.unwrap_or_else(|| args.get(1).cloned().unwrap_or(SynValue::Nothing)))
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_incr", -1, Rc::new(move |_i, args, _l| {
            use synsema_core::number::Number;
            let key = key_arg(args, "state_incr")?;
            let delta = match args.get(1) {
                Some(SynValue::Number(n)) => n.clone(),
                _ => Number::Int(1),
            };
            let current = match load(host_kv, &l, &key, "state_incr")? {
                Some(SynValue::Number(n)) => n,
                _ => Number::Int(0),
            };
            // Entero cuando AMBOS son Int (contadores → JSON `1`, no `1.0`); Float si no.
            let new_val = match (&current, &delta) {
                (Number::Int(a), Number::Int(b)) => Number::Int(a + b),
                _ => Number::Float(current.to_f64() + delta.to_f64()),
            };
            let v = SynValue::Number(new_val);
            store(host_kv, &l, &key, &v);
            Ok(v)
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_delete", 1, Rc::new(move |_i, args, _l| {
            let key = key_arg(args, "state_delete")?;
            if host_kv {
                if let Some(p) = hostcap::provider() {
                    let _ = p.kv_delete(NS, &key);
                }
            } else {
                l.borrow_mut().shift_remove(&key);
            }
            Ok(syn_bool(true))
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_all", 0, Rc::new(move |_i, _args, _l| {
            let mut map = SynMap::new();
            if host_kv {
                if let Some(p) = hostcap::provider() {
                    let keys = match p.kv_list(NS) {
                        Some(Err(e)) => return Err(rt_err(&format!("state_all: host kv.list failed: {}", e))),
                        Some(Ok(keys)) => keys,
                        None => Vec::new(),
                    };
                    for k in keys {
                        if let Some(v) = load(true, &l, &k, "state_all")? {
                            map.insert(k, v);
                        }
                    }
                }
            } else {
                for (k, v) in l.borrow().iter() {
                    map.insert(k.clone(), v.clone());
                }
            }
            Ok(syn_map(map))
        }));
    }

    // v0.6.45 — `state_merge` y `state_cas`, atómicos como bajo `serve`. Sin KV del host el
    // estado es de esta instancia (un hilo): ya es atómico. Con KV del host puede ser compartido
    // entre instancias, y entonces sólo se promete atomicidad si el host ofrece `kv.cas`: si no,
    // error claro (leer-modificar-guardar perdería escrituras concurrentes en silencio).
    const CAS_ATTEMPTS: usize = 64;
    fn host_cas(who: &str) -> Result<Rc<dyn HostProvider>, Control> {
        match hostcap::provider() {
            Some(p) if p.offers("kv_cas") => Ok(p),
            _ => Err(rt_err(&format!(
                "{}: the host's kv does not offer cas (kv.cas), so this update would not be atomic across instances; offer kv.cas, or use state_set if one writer is enough",
                who
            ))),
        }
    }
    /// v0.6.46: una lectura que falla es un error de la operación (antes, `nothing`).
    fn raw_of(p: &Rc<dyn HostProvider>, key: &str, who: &str) -> Result<Option<String>, Control> {
        match p.kv_get(NS, key) {
            Some(Err(e)) => Err(rt_err(&format!("{}: host kv.get failed: {}", who, e))),
            Some(Ok(v)) => Ok(v),
            None => Ok(None),
        }
    }
    /// v0.6.46 (ronda 2 de cf1, R2-B3): un texto que no es JSON es error, no `nothing` (que
    /// `state_update` o un `state_cas(k, nothing, ..)` lo pisaran).
    fn value_of(raw: &Option<String>, key: &str, who: &str) -> Result<SynValue, Control> {
        match raw.as_deref() {
            None => Ok(SynValue::Nothing),
            Some(r) => match serde_json::from_str::<serde_json::Value>(r) {
                Ok(v) => Ok(json_to_syn(&v)),
                Err(e) => Err(rt_err(&format!("{}: the stored value of '{}' is not JSON ({})", who, key, e))),
            },
        }
    }
    fn merged(who: &str, key: &str, current: &SynValue, patch: &synsema_core::types::MapRef) -> Result<SynValue, Control> {
        let mut out = SynMap::new();
        match current {
            SynValue::Nothing => {}
            SynValue::Map(m) => {
                for (k, v) in m.borrow().iter() {
                    out.insert(k.clone(), v.clone());
                }
            }
            other => {
                return Err(rt_err(&format!(
                    "{}: the value of '{}' is {}, not a map — use state_set to replace it",
                    who,
                    key,
                    other.type_name()
                )))
            }
        }
        for (k, v) in patch.borrow().iter() {
            out.insert(k.clone(), v.clone());
        }
        Ok(syn_map(out))
    }
    {
        let l = local.clone();
        interp.register_builtin("state_merge", 2, Rc::new(move |_i, args, _l| {
            const F: &str = "state_merge";
            let key = key_arg(args, F)?;
            let patch = match args.get(1) {
                Some(SynValue::Map(m)) => m.clone(),
                Some(other) => return Err(rt_err(&format!("{}: the second argument must be a map, got {}", F, other.type_name()))),
                None => return Err(rt_err(&format!("{}: missing the map to merge", F))),
            };
            if !host_kv {
                let current = l.borrow().get(&key).cloned().unwrap_or(SynValue::Nothing);
                let v = merged(F, &key, &current, &patch)?;
                l.borrow_mut().insert(key, v.clone());
                return Ok(v);
            }
            let p = host_cas(F)?;
            for _ in 0..CAS_ATTEMPTS {
                let raw = raw_of(&p, &key, F)?;
                let v = merged(F, &key, &value_of(&raw, &key, F)?, &patch)?;
                match p.kv_cas(NS, &key, raw.as_deref(), &dumps_syn(&v)) {
                    Some(Ok(true)) => return Ok(v),
                    Some(Ok(false)) => continue,
                    Some(Err(e)) => return Err(rt_err(&format!("{}: host kv: {}", F, e))),
                    // v0.6.45: el host no contestó el cas (antes salía como "kept changing").
                    None => return Err(rt_err(&format!("{}: the host's kv.cas did not answer", F))),
                }
            }
            Err(rt_err(&format!("{}: '{}' kept changing under concurrent writers ({} attempts)", F, key, CAS_ATTEMPTS)))
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_cas", 3, Rc::new(move |_i, args, _l| {
            const F: &str = "state_cas";
            let key = key_arg(args, F)?;
            let expected = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            let new = args.get(2).cloned().unwrap_or(SynValue::Nothing);
            if !host_kv {
                let current = l.borrow().get(&key).cloned().unwrap_or(SynValue::Nothing);
                if !current.syn_equals(&expected) {
                    return Ok(SynValue::Bool(false));
                }
                l.borrow_mut().insert(key, new);
                return Ok(SynValue::Bool(true));
            }
            let p = host_cas(F)?;
            // Igualdad del LENGUAJE (`2.0 == 2`): se compara el valor leído y se escribe con `cas`
            // contra el texto EXACTO que se leyó; si otro escribió en el medio, se vuelve a leer.
            for _ in 0..CAS_ATTEMPTS {
                let raw = raw_of(&p, &key, F)?;
                if !value_of(&raw, &key, F)?.syn_equals(&expected) {
                    return Ok(SynValue::Bool(false));
                }
                match p.kv_cas(NS, &key, raw.as_deref(), &dumps_syn(&new)) {
                    Some(Ok(true)) => return Ok(SynValue::Bool(true)),
                    Some(Ok(false)) => continue,
                    Some(Err(e)) => return Err(rt_err(&format!("{}: host kv: {}", F, e))),
                    // v0.6.45: el host no contestó el cas (antes salía como "kept changing").
                    None => return Err(rt_err(&format!("{}: the host's kv.cas did not answer", F))),
                }
            }
            Err(rt_err(&format!("{}: '{}' kept changing under concurrent writers ({} attempts)", F, key, CAS_ATTEMPTS)))
        }));
    }
}

// Los stubs del perfil puro (sockets/DB/cron/hub/archivos/hilos) viven en
// `synsema_stdlib::pure`: una sola lista para el nativo `--profile pure` y los dos
// artefactos wasm (misma verdad del entorno, mismo texto salvo el hint).

// =========================================================
// run / test / check
// =========================================================

fn parse_errors(e: CompileError) -> String {
    match e {
        CompileError::Lex(e) => format!("Lexer error: {}", e),
        CompileError::Parse(e) => format!("Parse error: {}", e),
    }
}

fn env_store(opts: &RunOptions) -> Rc<EnvStore> {
    Rc::new(match &opts.env {
        Some(vars) => EnvStore::from_vars(vars.clone()),
        None => EnvStore::load_default(),
    })
}

/// v0.6.45 (D2) — arma los límites de la corrida (o del request, en el modo handler) y prende la
/// bandera de cancelación para que el chequeo por sentencia los mire. Sin límites pedidos, desarma
/// y deja el camino de siempre. Un `reset_for_request` pone un token nuevo con la bandera apagada:
/// por eso el handler la vuelve a armar antes de cada request (antes los límites valían sólo en el
/// primero).
pub(crate) fn arm_limits(interp: &mut Interpreter, opts: &RunOptions) {
    #[cfg(target_arch = "wasm32")]
    {
        synsema_core::wasm_limits::disarm();
        if opts.max_steps.is_some() || opts.max_memory_mb.is_some() {
            let bytes = opts.max_memory_mb.map(|mb| mb.saturating_mul(1 << 20));
            synsema_core::wasm_limits::arm(opts.max_steps, bytes, interp.steps());
            let token = synsema_core::interpreter::CancelToken::new();
            token.flag.store(true, std::sync::atomic::Ordering::Relaxed);
            interp.set_cancel_token(token);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (interp, opts);
}

/// Desarma los límites al terminar (una corrida, el top-level del handler o un request).
pub(crate) fn disarm_limits() {
    #[cfg(target_arch = "wasm32")]
    synsema_core::wasm_limits::disarm();
}

/// Intérprete + CapabilitySet cableados para `program`, con el techo aplicado ANTES
/// de los auto-grants (idéntico al runtime).
pub(crate) fn prepare(program: &Program, opts: &RunOptions) -> (Interpreter, Rc<RefCell<CapabilitySet>>) {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    if let Some(cl) = &opts.ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new(cl.clone()));
    }
    // v0.6.45 (D2): los límites de ESTA corrida (los de una anterior nunca se cuelan). Con alguno
    // pedido, la bandera de cancelación queda prendida para que el chequeo por sentencia que ya
    // existe los mire (ver `synsema_core::wasm_limits`); sin límites, el camino de siempre.
    arm_limits(&mut interp, opts);
    let ctx = WireCtx { env: env_store(opts), statements: &program.statements, filename: &opts.filename, no_fs: opts.no_fs };
    wire_pure(&mut interp, &caps, &ctx);
    // v0.6.46 (E3b): los módulos de confianza del embebedor, con el mismo helper que el nativo.
    if !opts.trusted.is_empty() {
        synsema_stdlib::captoken::install_trusted_modules(&mut interp, caps.clone(), &opts.trusted, &opts.trusted_templates, opts.trusted_ceiling.clone());
    }
    if opts.labels {
        interp.set_labels(true);
        interp.set_labels_detail_to_program(opts.labels_detail_to_program);
        // v0.6.45 (D1): los MISMOS sumideros que el nativo (una sola lista, `label_lists`). Antes el
        // wasm encendía las etiquetas sin registrar ninguno: `print` redactaba, pero `fetch`/`http_*`
        // hacia el hook del host, `state_set` al KV y `remember` salían con el dato en claro (en
        // nativo los mismos programas daban `label_violation`). Un nombre que el wasm no tiene se
        // ignora, como en el nativo.
        for name in synsema_stdlib::label_lists::LABEL_SINK_BUILTINS
            .iter()
            .chain(synsema_core::interpreter::CORE_SINK_BUILTINS.iter())
            .chain(synsema_stdlib::label_lists::WASM_EXTRA_SINK_BUILTINS.iter())
        {
            interp.register_label_sink(name);
        }
    }
    (interp, caps)
}

/// Liga la entrada del host (`RunOptions.input`) como variable global, con
/// las FUENTES marcadas desde Rust: cada clave de `sources` presente y no-`nothing` pasa a
/// `private(valor, principales)`. Error (no silencio) si hay fuentes sin etiquetas o si la
/// entrada no es un mapa y se pidieron fuentes por clave.
fn bind_input(interp: &Interpreter, opts: &RunOptions) -> Result<(), String> {
    let Some((var, value)) = &opts.input else {
        if !opts.sources.is_empty() {
            return Err("sources were given without an input".to_string());
        }
        return Ok(());
    };
    if var.is_empty() {
        return Err("input: the variable name is empty".to_string());
    }
    let v = synsema_stdlib::json::json_to_syn(value);
    if !opts.sources.is_empty() {
        if !opts.labels {
            return Err("sources need labels: true (there is no Private variant to mark the input with)".to_string());
        }
        let SynValue::Map(m) = &v else {
            return Err("sources: the input must be a map to label its keys".to_string());
        };
        let mut map = m.borrow_mut();
        for (key, principals) in &opts.sources {
            if principals.is_empty() {
                return Err(format!("sources.{}: at least one principal is required", key));
            }
            if let Some(cur) = map.get(key.as_str()) {
                if matches!(cur, SynValue::Nothing) {
                    continue;
                }
                let marked = synsema_core::labels::mark(cur.clone(), synsema_core::labels::label_from(principals));
                map.insert(key.clone(), marked);
            }
        }
    }
    interp.set_global(var, v);
    Ok(())
}

pub(crate) fn finish(mut interp: Interpreter, result: Result<SynValue, Control>) -> RunResult {
    finish_keep(&mut interp, result)
}

/// Como `finish` pero sin consumir el intérprete (el handler-mode lo conserva).
pub(crate) fn finish_keep(interp: &mut Interpreter, result: Result<SynValue, Control>) -> RunResult {
    disarm_limits();
    // T5 (ronda 6, B2): la salida de una corrida cortada por el chequeo de flujo no se entrega
    // — la cantidad de líneas antes del corte depende del dato privado. Bajo el guest esas
    // líneas son el log del Executor, que vive FUERA del enclave.
    interp.redact_output_for_host(&result);
    match result {
        Ok(_) => RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new(), ..Default::default() },
        // Ronda 7: si el corte lo decidió el sistema de etiquetas, el error sale SIN ubicación —
        // cuál de N sitios murió depende del dato, y bajo el guest este texto cruza al Executor.
        Err(Control::Error(e)) => RunResult {
            success: false,
            output: std::mem::take(&mut interp.output),
            errors: vec![format!("Runtime error: {}", e.to_string_for_client())],
            ..Default::default()
        },
        Err(Control::Give(_)) | Err(Control::Stop(_)) => RunResult {
            success: false,
            output: std::mem::take(&mut interp.output),
            errors: vec!["Runtime error: 'give'/'stop' used outside of a task or loop".to_string()],
            ..Default::default()
        },
    }
}

/// Corre el programa. Nunca panica por un error del programa: parse/runtime van a
/// `errors`; la salida de `print` a `output` (el core la colecta con
/// `live_output = false` — no se toca stdout).
/// v0.6.45 (D1) — los builtins que registra el wasm para `opts`, con el host que esté instalado
/// en este hilo (`hostcap::install`), ordenados. Es la fuente del anti-rot de etiquetas del wasm
/// (`tests/labels_host_sinks.rs`): la clasificación se cruza con lo registrado de verdad.
pub fn registered_builtin_names(opts: &RunOptions) -> Vec<String> {
    let program = match parse_source("", &opts.filename) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let (interp, _caps) = prepare(&program, opts);
    let env = interp.global_env.borrow();
    let mut names: Vec<String> = env
        .bindings
        .iter()
        .filter(|(_, v)| matches!(v, synsema_core::types::SynValue::Builtin(_)))
        .map(|(k, _)| k.to_string())
        .collect();
    names.sort();
    names
}

pub fn run(source: &str, opts: &RunOptions) -> Report {
    let program = match parse_source(source, &opts.filename) {
        Err(e) => {
            return Report {
                ok: false,
                output: Vec::new(),
                errors: vec![parse_errors(e)],
                audit: Vec::new(),
                llm_tokens: 0,
                steps: 0,
                result: None,
                declassify: Vec::new(),
                private_seen: false,
                exit_code: None,
                receipt: None,
                operator_detail: None,
            }
        }
        Ok(p) => p,
    };
    // v0.6.46 (E6): el registro de la corrida, en este hilo y mientras dure la corrida (desde el
    // wiring: los grants ambientales también son entradas).
    let started = synsema_stdlib::receipt::rfc3339_utc(synsema_core::clock::now_secs());
    let sealed_log = opts.auditor.map(|_| synsema_stdlib::sealed::new_run_log(opts.sealed_bytes.unwrap_or(synsema_stdlib::sealed::DEFAULT_SEALED_BYTES)));
    let _sealed = sealed_log.clone().map(synsema_core::sealed::install_thread);
    let (mut interp, caps) = prepare(&program, opts);
    if let Err(e) = bind_input(&interp, opts) {
        disarm_limits(); // ronda 2 (M1): esta salida no pasa por `finish`
        return Report {
            ok: false,
            output: Vec::new(),
            errors: vec![format!("input: {}", e)],
            audit: Vec::new(),
            llm_tokens: 0,
            steps: 0,
            result: None,
            declassify: Vec::new(),
            private_seen: false,
            exit_code: None,
            receipt: None,
            operator_detail: None,
        };
    }
    let result = interp.execute(&program);
    let steps = interp.steps();
    let private_seen = interp.private_seen();
    // El valor pedido se lee del entorno GLOBAL tal cual quedó (etiquetas incluidas) y sólo
    // Si la corrida terminó bien: un programa que falló no tiene un resultado que entregar.
    let value = match (&opts.result, &result) {
        (Some(name), Ok(_)) => interp.global_env.borrow().bindings.get(name).map(labelled_json),
        _ => None,
    };
    let declared = interp.declared_principals_list();
    let declassify = interp
        .take_declassify_log()
        .into_iter()
        // v0.6.46 (E6.8): las declasificaciones de una rama privada no salen al host: cuántas hubo
        // decía qué rama se tomó.
        .filter(|e| !e.under_private_pc)
        .map(|e| DeclassifyRecord {
            reason: e.reason,
            // T5 (ronda 7): el `from` que sale al host es el conjunto DECLARADO por el programa,
            // no la etiqueta de ese valor — ésa varía con cuál se seleccionó y publica el dato.
            from: declared.clone(),
            to: e.to.iter().map(|s| s.to_string()).collect(),
            line: e.loc.line,
            column: e.loc.column,
        })
        .collect();
    let exit_code = match &result {
        Err(Control::Error(e)) => e.exit_code,
        _ => None,
    };
    let operator_detail = match &result {
        Err(Control::Error(e)) => e.operator_detail.clone(),
        _ => None,
    };
    let r = finish(interp, result);
    let receipt = match (&sealed_log, opts.auditor) {
        (Some(log), Some(auditor)) => {
            let key = synsema_stdlib::sealed::RunKey::ephemeral();
            let program_sha = Some(synsema_core::bytesutil::hex_encode(&synsema_stdlib::attest::sha256(source.as_bytes())));
            let log = log.lock().unwrap_or_else(|p| p.into_inner());
            match synsema_stdlib::sealed::build_receipt(
                &log,
                &synsema_stdlib::sealed::ReceiptContext { auditor, key: &key, program_sha, config_sha: None, trusted: synsema_stdlib::sealed::trusted_shas(&opts.trusted, &opts.trusted_templates), started },
            ) {
                Ok(v) => Some(v),
                // Sin recibo no hay salida: es lo que el host pidió al poner un auditor.
                Err(e) => {
                    return Report {
                        ok: false,
                        output: Vec::new(),
                        errors: vec![format!("the sealed receipt could not be built: {}", e)],
                        audit: Vec::new(),
                        llm_tokens: 0,
                        steps: 0,
                        result: None,
                        declassify: Vec::new(),
                        private_seen,
                        exit_code: None,
                        receipt: None,
                        operator_detail: None,
                    }
                }
            }
        }
        _ => None,
    };
    Report {
        receipt,
        ok: exit_code.map_or(r.success, |c| c == 0),
        output: r.output,
        // `exit` no es un error: el programa pidió terminar.
        errors: if exit_code.is_some() { Vec::new() } else { r.errors },
        exit_code,
        audit: export_audit(&caps),
        llm_tokens: llm_tokens_total(),
        steps,
        result: value,
        declassify,
        private_seen,
        operator_detail,
    }
}

/// Corre los bloques `test` del archivo con el mismo wiring puro.
pub fn test(source: &str, opts: &RunOptions) -> TestReport {
    let program = match parse_source(source, &opts.filename) {
        Err(e) => return TestReport { passed: 0, failed: 1, lines: vec![parse_errors(e)], audit: Vec::new() },
        Ok(p) => p,
    };
    let (mut interp, caps) = prepare(&program, opts);
    let outcomes = interp.run_test_blocks(&program);
    disarm_limits(); // ronda 2 (M1): `test` no pasa por `finish`
    let mut lines = Vec::with_capacity(outcomes.len());
    let mut passed = 0usize;
    for o in &outcomes {
        if o.passed {
            passed += 1;
            lines.push(format!("  ok  {}", o.name));
        } else {
            let msg = o.message.clone().unwrap_or_default();
            lines.push(format!("FAIL  {} — {}", o.name, msg));
        }
    }
    let failed = outcomes.len() - passed;
    TestReport { passed, failed, lines, audit: export_audit(&caps) }
}

/// Parse + validaciones estáticas (sin ejecutar): lexer/parser y la declaración de
/// memoria (nombre válido, una sola identidad).
pub fn check(source: &str, filename: &str) -> CheckReport {
    let program = match parse_source(source, filename) {
        Err(e) => return CheckReport { ok: false, errors: vec![parse_errors(e)] },
        Ok(p) => p,
    };
    let mut errors = Vec::new();
    if let Err(e) = declared_memory_name(&program.statements) {
        errors.push(e);
    }
    CheckReport { ok: errors.is_empty(), errors }
}

pub use handler::{handle, HandleReport, HttpRequestIn, HttpResponseOut};

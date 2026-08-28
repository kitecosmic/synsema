//! Templates de `synsema init` (Spec DX-2). REGLA anti-rot: los templates están
//! TEST-VERIFICADOS contra el engine — un template equivocado enseña mal a escala,
//! peor que no tenerlo. Ver el `mod tests` de abajo:
//! - `hello.syn` debe PARSEAR con el parser real.
//! - Toda env-var mencionada en `.env.example` debe existir en la lista canónica del
//!   runtime (`LLM_ENV_VARS`), y toda var de la lista debe estar en el template o en el
//!   allowlist local-only del test → agregar un knob sin tocar el template ROMPE el build.

/// Programa inicial: un tour corto de lo primordial del lenguaje (valores, tareas,
/// control de flujo, capacidades, LLM con degradación avisada, tests nativos), con
/// los punteros de skill/MCP para desarrollar con agentes desde el minuto 0.
pub const HELLO_SYN: &str = r#"-- Mi primer programa Synsema.
--   Correlo:   synsema run hello.syn
--   Testealo:  synsema test hello.syn
--
-- ¿Desarrollás con un agente (Claude Code o similar)? Potencialo desde el minuto 0
-- con DOS comandos (los pega el dev o el propio agente — sin clonar nada):
--   curl -sL https://raw.githubusercontent.com/kitecosmic/synsema/main/install-skill.sh | bash
--     (instala el skill: el agente escribe Synsema idiomático solo)
--   claude mcp add --transport http synsema-docs https://docs.synsema.com/mcp
--     (MCP de docs: busca doc con search/get y VERIFICA sus snippets con run/test en sandbox)
-- Docs para humanos: https://docs.synsema.com

intent: "Mi primer programa Synsema"

-- Capacidades: Synsema es deny-by-default — `require` declara lo que el programa puede
-- tocar (llm, net, file, db, memory, ...). Sin el permiso, la operación se deniega con
-- error claro.
require llm

-- Memoria persistente DECLARADA: esta línea habilita remember/recall (y reglas y
-- progreso) y le da IDENTIDAD al estado — el nombre declarado (no el nombre del
-- archivo) keyea `.synsema/state/hello.db` (el .gitignore generado ya lo excluye).
-- Sin esta línea, remember/recall se deniegan y NO se crea ningún archivo.
require memory("hello")

-- Valores: `let` declara (texto, número, lista, map).
let nombre be "mundo"
let numeros be [1, 2, 3]
let persona be {"nombre": "Ada", "edad": 36}

-- Tareas: funciones con `give` como retorno; params con default incluidos.
task greet(name, saludo = "hola")
    give saludo + " " + name

print(greet(nombre))                  -- => hola mundo
print(greet("Synsema", "buenas"))     -- => buenas Synsema

-- Control de flujo: iteración + when/otherwise.
each n in numeros
    when n > 1
        print("grande: " + text(n))
    otherwise
        print("chico: " + text(n))

print(persona["nombre"] + " tiene " + text(persona["edad"]))

-- Memoria del agente: sobrevive entre ejecuciones (gracias al `require memory` de
-- arriba). Corré el programa DOS veces y mirá el contador crecer — eso es un agente
-- que recuerda. `recall` filtra por categoría/tags/texto y devuelve lo más nuevo
-- primero; dentro de un `agent`, cada agente lee su propio namespace por defecto
-- (cruzá con `recall(from = "otro")`). Docs: https://docs.synsema.com → Memory & state.
remember("learning", "corrí el tour de hello.syn", ["tour"])
let memorias be recall("learning", ["tour"])
print("memorias del tour: " + text(length(memorias)) + " (corré de nuevo y crece)")

-- LLM nativo: con un provider conectado (ver .env.example) esto razona de verdad.
-- Sin provider, DEGRADA CON AVISO y el programa sigue — la cadena nunca se rompe.
when llm_available()
    let idea be reason about "una idea corta para mi primer proyecto Synsema"
    print(idea)
otherwise
    print("(LLM offline — corré `synsema llm status` para conectarlo)")

-- Tests nativos: los corre `synsema test hello.syn` (`run` los saltea).
test "greet saluda con y sin default"
    assert_eq(greet("Synsema"), "hola Synsema")
    assert_eq(greet("Synsema", "buenas"), "buenas Synsema")

test "la memoria declarada guarda y encuentra (más nuevo primero)"
    remember("learning", "nota del test", ["test-tour"])
    let notas be recall("learning", ["test-tour"])
    assert_eq((notas[0])["content"], "nota del test")
"#;

/// `.env.example`: cada variable comentada EN SU LÍNEA para que se entienda sola; los
/// providers como PARES indivisibles (provider + SU key) — el error "key bajo la
/// variable equivocada" costó un incidente real. ⚠️ el default de MAX_TOKENS es bajo.
pub const ENV_EXAMPLE: &str = r#"# Config del proyecto — Synsema auto-carga el `.env` de este directorio (sin export/source).
# Empezar:  copiá este archivo a `.env` y descomentá lo que uses.
# NO subas `.env` al repo (el .gitignore generado ya lo excluye).
#
# ¿Qué quedó configurado de verdad? →  synsema llm status
# (muestra cada valor RESUELTO con su fuente, y si está offline, qué variable falta)
#
# Agentes (Claude Code y similares) — desarrollo potenciado desde el minuto 0,
# DOS comandos y listo (en Windows, desde Git Bash el primero):
#   curl -sL https://raw.githubusercontent.com/kitecosmic/synsema/main/install-skill.sh | bash
#   claude mcp add --transport http synsema-docs https://docs.synsema.com/mcp

# ══ Provider LLM: elegí UN par (provider + SU key) y descomentá LAS DOS líneas ══
# La key va SIEMPRE bajo la variable de SU provider (con provider=minimax, la key va
# en MINIMAX_API_KEY). Si solo seteás la key, el provider se auto-selecciona.

# SYNSEMA_LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=sk-ant-...          # key de Anthropic (Claude)

# SYNSEMA_LLM_PROVIDER=openai
# OPENAI_API_KEY=sk-...                 # key de OpenAI (GPT)

# SYNSEMA_LLM_PROVIDER=minimax
# MINIMAX_API_KEY=...                   # key de MiniMax (M3)

# SYNSEMA_LLM_PROVIDER=deepseek
# DEEPSEEK_API_KEY=sk-...               # key de DeepSeek

# Modelo LOCAL en proceso (GGUF: sin red, sin key; binario con --features llm-local):
# SYNSEMA_LLM_PROVIDER=local
# SYNSEMA_LLM_MODEL=/ruta/al/modelo.gguf   # para `local`, MODEL es la RUTA al .gguf (obligatorio)

# ══ Knobs opcionales (todos con default sano; referencia: docs → 52-provider) ══

# Id del modelo — gana sobre el default del provider
# (defaults: claude-sonnet-4-6 / gpt-4o / MiniMax-M3 / deepseek-chat):
# SYNSEMA_LLM_MODEL=

# ⚠️ Tope de tokens de SALIDA por llamada. El default (4096) es MUY BAJO para generar
# archivos o código — se truncan a la mitad sin error. Si tu agente escribe archivos,
# subilo (verificado: con 20000 escribe archivos de >20 KB en un paso):
# SYNSEMA_LLM_MAX_TOKENS=20000

# Timeout HTTP en segundos. Con el transporte streaming (default) mide SILENCIO entre
# bytes — una generación de minutos fluye y un host muerto falla rápido igual:
# SYNSEMA_LLM_TIMEOUT=60

# Transporte streaming SSE interno de los providers de red. `0` = camino clásico
# no-stream (solo para proxies que se atragantan con SSE):
# SYNSEMA_LLM_HTTP_STREAM=1

# Endpoint alternativo OpenAI-compatible — modelos locales por server:
# Ollama http://localhost:11434/v1 · LM Studio · vLLM · llama.cpp:
# SYNSEMA_LLM_BASE_URL=

# Presupuesto DURO de tokens LLM del proceso (input+output, TODAS las ops). Al
# llegar al tope las ops degradan al marker "[llm budget exceeded: …]" sin tocar
# la red (nunca error). El consumo se consulta con llm_usage():
# SYNSEMA_LLM_BUDGET=

# ══ Techos del host — dinero y firmas (el programa NO puede subirlos) ══

# Techo de gasto por unidad para spend(monto, unidad, motivo): pares unidad:monto
# separados por comas. La unidad es texto LIBRE — fiat, cripto, commodities, creditos,
# kWh: el ledger no privilegia ninguna moneda y acepta hasta 28 decimales (una unidad
# de 18 decimales entra entera). Excederlo hace fallar spend() con error catchable —
# NO sigas con el pago externo. Acumulador por proceso; el ledger persistente queda
# en spend.log del dir de audit:
# SYNSEMA_SPEND_CEILING=EUR:500,ETH:0.1,bbl:100

# Techo de gasto POR IDENTIDAD de agente (T6.4): entradas identidad=UNIDAD:monto
# separadas por comas. Va en su propia variable —y no como entradas del techo de
# arriba— para que una unidad que contenga ':' jamas colisione con la clave de una
# identidad. Se aplica ADEMAS del techo por unidad: manda el mas restrictivo:
# SYNSEMA_SPEND_CEILING_PER_IDENTITY=agent-1=EUR:50,researcher=ETH:0.01

# Techo de CANTIDAD de firmas por clave (name del secret de la clave): pares
# clave:n separados por comas. La firma n+1 falla catchable y queda auditada:
# SYNSEMA_SIGN_CEILING=HOT_KEY:100

# Espera máxima (segundos) de approve/confirm/ask bajo serve antes de DENEGAR
# fail-closed (por-gate: `approve "..." within 2h` le gana a esta variable):
# SYNSEMA_HUMAN_TIMEOUT=300

# Webhook saliente de aprobaciones: cada gate encolado dispara un POST JSON con el
# token a esta URL (tu canal — otro serve Synsema, SMS, chat — es quien avisa al humano):
# SYNSEMA_HUMAN_WEBHOOK=

# Clave HMAC del webhook — firma el body en X-Synsema-Signature (sha256=<hex>).
# Sin ella el POST va SIN firmar: solo para dev local, en producción SIEMPRE:
# SYNSEMA_HUMAN_WEBHOOK_SECRET=

# Base pública de ESTE server — habilita los links listos para reenviar
# (respond_link_yes/no: el humano decide abriendo una URL desde SMS/chat):
# SYNSEMA_HUMAN_PUBLIC_URL=

# ══ Knobs del servidor (`synsema serve`) — SOLO del entorno del PROCESO ══

# Estos los lee el proceso al arrancar (export / systemd / Docker -e), NO este
# archivo: el .env alimenta env()/secret() y la config de LLM/humanos, no al runtime
# del server. Van listados aca para que nadie tenga que adivinarlos.

# Workers del pool de handlers sized (default: nucleos de la maquina; los stream y
# socket usan hilo propio y no consumen pool):
# SYNSEMA_SERVE_WORKERS=4

# Gracia (segundos) del shutdown ordenado ante SIGINT/SIGTERM: se dejan de aceptar
# requests (503 + Retry-After), se drenan las que estan en vuelo y al vencer se
# cancelan. 0 = inmediato. Un segundo Ctrl-C durante el drain sale ya (codigo 130):
# SYNSEMA_SHUTDOWN_GRACE=10

# Heartbeat de los `stream` SSE: comentario `: keepalive` (invisible para EventSource)
# tras N segundos sin frames, asi proxies y browsers no cortan streams ociosos. 0 apaga:
# SYNSEMA_SSE_KEEPALIVE=15

# Ping del server a cada `socket` (WebSocket entrante) cada N segundos mientras el
# handler espera en ws_recv/select; sin Pong en 2 intervalos el handler recibe `close`
# con reason "keepalive timeout". 0 apaga:
# SYNSEMA_WS_SERVER_PING=30

# Subprotocolos WebSocket que el server acepta acordar (separados por coma; se eco el
# primero que el cliente ofrezca). Sin la variable no se acuerda ninguno:
# SYNSEMA_WS_SUBPROTOCOLS=

# Tamanio maximo de un mensaje WebSocket entrante (mas grande = error atrapable en el
# handler, nunca un close mudo). Acepta 512KB, 16MB...; default 16MB, techo 64MB:
# SYNSEMA_WS_MAX_MESSAGE=16MB

# Conexiones WebSocket vivas por interprete — ws_connect + sockets entrantes (default 4096):
# SYNSEMA_WS_MAX_CONNS=4096

# Procesos vivos (proc_spawn) por interprete (default 64, techo duro 1024):
# SYNSEMA_PROC_MAX=64

# File-watches vivos (watch) por interprete (default 64, techo duro 1024; un hilo cada uno):
# SYNSEMA_WATCH_MAX=64

# ══ Secretos de TU programa (el nombre lo elegís vos, no el engine) ══

# `secret("NOMBRE")` resuelve por: entorno del proceso > este .env > default; sin
# ninguno de los tres, ERROR (nunca un valor vacío silencioso). El NOMBRE es tambien
# lo que scopea la capability: `require secret("JWT_KEY")` habilita ESE secreto y no
# otro, y `require sign("AGENT_SIGNING_KEY")` habilita firmar SOLO con esa clave.
# El valor jamas se imprime ni viaja a un LLM: sale como `secret(NOMBRE)`.
# Los de abajo son los que piden las features de auth — borra los que no uses y
# agrega los tuyos con el mismo patron (API keys de terceros, webhooks, etc.).

# Clave con la que firmas y verificas TUS tokens de sesion — jwt_sign/jwt_verify.
# Cualquier texto largo y aleatorio sirve; generalo con: synsema repl → token()
# JWT_KEY=

# Clave RAIZ de los tokens de capacidad — captoken_mint/captoken_verify.
# Atenuar NO la necesita (por eso un subagente delegado nunca la ve):
# CAPTOKEN_ROOT_KEY=

# Clave con la que tu agente FIRMA sus requests salientes — http_sign.
# ed25519 en hex, o texto crudo si usas alg "hmac-sha256". Necesita ademas
# `require sign("AGENT_SIGNING_KEY")` en el programa (deny-by-default + auditado):
# AGENT_SIGNING_KEY=
"#;

pub const GITIGNORE: &str = r#"# Secretos / config local — nunca subir
.env

# Estado del runtime Synsema
.synsema/
"#;

/// Un archivo que `synsema init` genera, con la PROCEDENCIA de sus versiones
/// anteriores.
///
/// `past` son los sha256 de todo contenido que este archivo tuvo en versiones
/// previas del engine. Existir NO es lo mismo que ser tuyo: sin esta lista, un
/// `.env.example` intacto de hace tres releases se confundía con uno editado y
/// jamás recibía las variables nuevas (el usuario ni se enteraba de que existían).
/// Con ella el upgrade distingue los tres estados reales — al día / de fábrica pero
/// viejo / con ediciones tuyas — y sólo el último se conserva.
pub struct InitFile {
    pub name: &'static str,
    pub content: &'static str,
    pub past: &'static [&'static str],
}

/// sha256 de cada contenido histórico de `hello.syn` (ver `InitFile::past`).
const HELLO_SYN_PAST: &[&str] = &[
    "e69804e5b0779fd4cea54a6c89d54719c75784960b3b2bafba145121ea0e74d8",
    "ef8518377fa71f6a4bd503670b3432a6c567ff502dab81273b17c66c1794b051",
    "e5acaf4f81afd7d5b6ad09d1892d772f45e731244956298ec556f8e5859e637d",
];

/// sha256 de cada contenido histórico de `.env.example` (ver `InitFile::past`).
const ENV_EXAMPLE_PAST: &[&str] = &[
    "89ce5ec7987119a7bf7579f74b93275ca3a61790766a143e06df26000b992bb9",
    // v0.6.6 (antes de la sección de knobs del servidor)
    "5e1b399a09adeb2b0dcc02e4fcdc6f0141d71dfa8a8a679f9ec2548b543f966a",
    "2e2abfde4bfafc3e97b44c5caa20c66b945be4adb178693dc89aae0325ab0ea5",
    "018e2caaad5b937d3f7f8e3866720f5225996f74f0ed5075848a85a9ebcb853b",
    "5a38c2ef0ac9c5ec66c2902e0c4b90a0e2083e1b3234036a2cbe7dc14e79da7e",
    "2f5fb20f6175b65bde78669a20e7565cff513cd5f18668bc46c7e42b4827fa70",
    "8905d8b18d42449dc712dd9125cd11d49448e92c89b0e5c9c605821da4a3ccbe",
    "439f3ab927a92bd090d281bb4aeb9052b295fa7cb55bab62f1a1819bfd464777",
    // v0.6.8 (antes de SYNSEMA_WATCH_MAX) y v0.6.9 (con él, sin el fix del knob)
    "2228ce300d028873345409bb4e2aad0e5e72222f675580a5ccddb7c51a3e59cc",
    "3f1e65e2d9b87302d4183381b92d26965b2db49dc7225a5056c124a7da16f1b2",
];

/// sha256 de cada contenido histórico de `.gitignore` (ver `InitFile::past`).
const GITIGNORE_PAST: &[&str] =
    &["20b449a6499a877f4e5a58d94be5ba3eabf779e2cdfadc1fecf0989a3e9a6314"];

/// Los tres archivos que `synsema init` genera, en orden.
pub const INIT_FILES: [InitFile; 3] = [
    InitFile { name: "hello.syn", content: HELLO_SYN, past: HELLO_SYN_PAST },
    InitFile { name: ".env.example", content: ENV_EXAMPLE, past: ENV_EXAMPLE_PAST },
    InitFile { name: ".gitignore", content: GITIGNORE, past: GITIGNORE_PAST },
];

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_runtime::llm_providers::{HUMAN_ENV_VARS, LLM_ENV_VARS};
    use synsema_stdlib::spend::CEILING_ENV_VARS;

    /// Anti-rot 5: la lista de procedencia está COMPLETA — se deriva de git y se
    /// compara con la declarada.
    ///
    /// Éste es el guard que hace segura toda la mecánica: `past` sólo sirve si
    /// contiene TODOS los contenidos anteriores. Si alguien edita un template y se
    /// olvida de agregar el sha del contenido viejo, cada proyecto existente que lo
    /// tenga pasa a clasificarse como "editado por el usuario" y nunca más recibe
    /// novedades — en silencio, que es como este bug llegó a producción la primera
    /// vez. Acá falla el build y el mensaje trae la línea exacta para pegar.
    ///
    /// Se saltea si el repo es shallow o no hay git (tarball, sandbox): es un guard
    /// de desarrollo, no una dependencia dura del build.
    #[test]
    fn init_file_history_is_complete() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("repo root")
            .to_path_buf();
        let rel = "engine/crates/synsema-cli/src/init_templates.rs";
        let git = |args: &[&str]| -> Option<String> {
            let o = std::process::Command::new("git").args(args).current_dir(&root).output().ok()?;
            o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
        };
        let Some(shallow) = git(&["rev-parse", "--is-shallow-repository"]) else {
            eprintln!("(sin git: se saltea el chequeo de historia)");
            return;
        };
        if shallow.trim() == "true" {
            eprintln!("(repo shallow: se saltea el chequeo de historia)");
            return;
        }
        let Some(log) = git(&["log", "--format=%H", "--reverse", "--", rel]) else { return };
        for f in INIT_FILES {
            let marker = format!(
                "pub const {}: &str = r#\"",
                match f.name {
                    "hello.syn" => "HELLO_SYN",
                    ".env.example" => "ENV_EXAMPLE",
                    _ => "GITIGNORE",
                }
            );
            let current = sha256_of(f.content);
            let mut missing: Vec<String> = Vec::new();
            for c in log.split_whitespace() {
                let Some(src) = git(&["show", &format!("{}:{}", c, rel)]) else { continue };
                let Some(i) = src.find(&marker) else { continue };
                let body = &src[i + marker.len()..];
                let Some(j) = body.find("\"#;") else { continue };
                let h = sha256_of(&body[..j]);
                if h != current && !f.past.contains(&h.as_str()) && !missing.contains(&h) {
                    missing.push(h);
                }
            }
            assert!(
                missing.is_empty(),
                "{}: faltan {} sha256 en su lista `past` — sin ellos, todo proyecto que                  tenga esa versión queda marcado como editado y no recibe novedades.                  Agregá estas líneas:
{}",
                f.name,
                missing.len(),
                missing.iter().map(|h| format!("    \"{}\",", h)).collect::<Vec<_>>().join("
")
            );
        }
    }

    /// Anti-rot 4: la lista de procedencia de cada archivo del scaffold está sana.
    ///
    /// `InitFile::past` es lo que permite distinguir "de fábrica pero viejo" de
    /// "editado por vos". **Al cambiar un template hay que agregar el sha256 del
    /// contenido ANTERIOR a su lista** — si no, todo proyecto que lo tenga queda
    /// clasificado como editado y nunca más recibe novedades (ese fue el bug real).
    /// Se puede recalcular la lista entera desde git:
    /// `git log --reverse -- init_templates.rs` + sha256 del literal de cada commit.
    #[test]
    fn init_file_provenance_is_well_formed() {
        for f in INIT_FILES {
            let current = sha256_of(f.content);
            for h in f.past {
                assert_eq!(h.len(), 64, "{}: '{}' no es un sha256", f.name, h);
                assert!(
                    h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "{}: '{}' debe ser hex en minúsculas",
                    f.name,
                    h
                );
                assert_ne!(
                    *h, current,
                    "{}: el contenido ACTUAL no va en `past` (se compara aparte)",
                    f.name
                );
            }
            let mut seen: Vec<&str> = Vec::new();
            for h in f.past {
                assert!(!seen.contains(h), "{}: sha duplicado en `past`: {}", f.name, h);
                seen.push(h);
            }
        }
    }

    fn sha256_of(s: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    }

    // Anti-rot 1: el hello.syn del template PARSEA con el parser real del engine.
    #[test]
    fn hello_syn_parses() {
        match synsema_core::parser::parse_source(HELLO_SYN, "hello.syn") {
            Ok(p) => assert!(p.statements.len() > 5, "template sospechosamente vacío"),
            Err(e) => panic!("el template hello.syn NO parsea: {:?}", e),
        }
    }

    /// Extrae los nombres de env-vars del runtime mencionados en un texto
    /// (`SYNSEMA_*` — no sólo LLM — y `*_API_KEY`).
    fn mentioned_vars(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            let is_knob_var = (token.starts_with("SYNSEMA_") && token.len() > "SYNSEMA_".len())
                || (token.ends_with("_API_KEY") && token.len() > "_API_KEY".len());
            if is_knob_var && !out.contains(&token.to_string()) {
                out.push(token.to_string());
            }
        }
        out
    }

    // Anti-rot 2: sincronía template ↔ engine. (a) Toda var mencionada en .env.example
    // existe en las listas canónicas del runtime (LLM ∪ humanas). (b) Toda var de las
    // listas está en el template O en el allowlist de vars que NO van al template por
    // diseño (knobs solo-local documentados en docs 52; vars circulares/nicho).
    // Agregar un knob `SYNSEMA_*` nuevo al runtime sin tocar el template (o este
    // allowlist, a conciencia) ROMPE este test — el template no puede desincronizarse
    // en silencio.
    #[test]
    fn env_example_in_sync_with_engine_knobs() {
        const OK_TO_OMIT_FROM_TEMPLATE: [&str; 7] = [
            // knobs solo-local (documentados en docs 52; no van al template para no abrumar)
            "SYNSEMA_LLM_CTX",
            "SYNSEMA_LLM_THREADS",
            "SYNSEMA_LLM_TEMPERATURE",
            "SYNSEMA_LLM_MAX_CONCURRENT",
            "SYNSEMA_LLM_STREAM_BUFFER",
            // la setean los flags del CLI (--env-file) — ponerla en un `.env` sería circular
            "SYNSEMA_ENV_FILE",
            // nicho: relocaliza el estado (.synsema/state) — no es config de proyecto típica
            "SYNSEMA_STATE_DIR",
        ];
        let canonical: Vec<&str> = LLM_ENV_VARS
            .iter()
            .chain(HUMAN_ENV_VARS.iter())
            .chain(CEILING_ENV_VARS.iter())
            .chain(synsema_stdlib::server::SERVE_ENV_VARS.iter())
            .copied()
            .collect();
        let mentioned = mentioned_vars(ENV_EXAMPLE);
        for var in &mentioned {
            assert!(
                canonical.contains(&var.as_str()),
                "el template menciona '{}' que el runtime NO conoce (¿typo o knob eliminado?)",
                var
            );
        }
        for var in &canonical {
            let covered =
                mentioned.iter().any(|m| m == var) || OK_TO_OMIT_FROM_TEMPLATE.contains(var);
            assert!(
                covered,
                "el knob '{}' del runtime NO está en el .env.example de `init` ni en el \
                 allowlist OK_TO_OMIT_FROM_TEMPLATE — actualizá el template (o el \
                 allowlist, a conciencia)",
                var
            );
        }
    }

    // Anti-rot 3: los pares provider+key van JUNTOS (la línea de la key aparece después
    // de la de su provider dentro del mismo bloque) — el agrupamiento es el fix del
    // incidente "key bajo la variable equivocada".
    #[test]
    fn env_example_groups_provider_key_pairs() {
        for (prov, key) in [
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("minimax", "MINIMAX_API_KEY"),
            ("deepseek", "DEEPSEEK_API_KEY"),
        ] {
            let p = ENV_EXAMPLE
                .find(&format!("SYNSEMA_LLM_PROVIDER={}", prov))
                .unwrap_or_else(|| panic!("falta el par de {}", prov));
            // Buscar la LÍNEA DE ASIGNACIÓN (`KEY=`), no menciones en prosa.
            let k = ENV_EXAMPLE
                .find(&format!("{}=", key))
                .unwrap_or_else(|| panic!("falta la asignación de {}", key));
            assert!(k > p && k - p < 200, "la key {} no está pegada a su provider", key);
        }
    }

    // El .gitignore protege el .env real.
    #[test]
    fn gitignore_covers_env_and_state() {
        assert!(GITIGNORE.contains(".env"));
        assert!(GITIGNORE.contains(".synsema/"));
    }
}

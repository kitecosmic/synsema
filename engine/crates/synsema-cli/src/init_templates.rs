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
-- tocar (llm, net, file, db, ...). Sin el permiso, la operación se deniega con error claro.
require llm

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

# Espera máxima (segundos) de approve/confirm/ask bajo serve antes de DENEGAR
# fail-closed (por-gate: `approve "..." within 2h` le gana a esta variable):
# SYNSEMA_HUMAN_TIMEOUT=300
"#;

pub const GITIGNORE: &str = r#"# Secretos / config local — nunca subir
.env

# Estado del runtime Synsema
.synsema/
"#;

/// Los tres archivos que `synsema init` genera, en orden.
pub const INIT_FILES: [(&str, &str); 3] = [
    ("hello.syn", HELLO_SYN),
    (".env.example", ENV_EXAMPLE),
    (".gitignore", GITIGNORE),
];

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_runtime::llm_providers::{HUMAN_ENV_VARS, LLM_ENV_VARS};

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
        let canonical: Vec<&str> =
            LLM_ENV_VARS.iter().chain(HUMAN_ENV_VARS.iter()).copied().collect();
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

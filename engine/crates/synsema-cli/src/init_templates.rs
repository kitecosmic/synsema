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
--   El .mcp.json de esta carpeta ya registra `synsema-code` (synsema code --mcp): outline,
--     routes, refs, caps, check, search sobre TU código sin leer archivos enteros.
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

# Profundidad maxima de run_program() anidado (un hijo que a su vez corre run_program,
# y asi): cada nivel es un proceso del mismo binario bajo techo ∩ padre. Default 4:
# SYNSEMA_RUN_PROGRAM_MAX_DEPTH=4

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
    // v0.6.12 (antes del puntero a `synsema code` / .mcp.json)
    "d490f12d6f562f108730243f75586ce598bd38caa25d98f8abcfc00a7680390a",
    "e69804e5b0779fd4cea54a6c89d54719c75784960b3b2bafba145121ea0e74d8",
    "ef8518377fa71f6a4bd503670b3432a6c567ff502dab81273b17c66c1794b051",
    "e5acaf4f81afd7d5b6ad09d1892d772f45e731244956298ec556f8e5859e637d",
    // v0.6.13 (a69d6ae): el hello.syn que ship con `synsema code` — su sha nunca se
    // agregó a `past` (el guard se saltea en CI shallow), así que estaba latente.
    "2212d1b3304687f23f48a26833dc0616ca0a99d121f42285156236657d554bd3",
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
    // Formas LF (lo que el binario escribe de verdad) de versiones commiteadas con CRLF:
    // el guard las hasheaba con CRLF y esos shas jamás coincidían con un archivo real.
    // Detectadas al normalizar el guard (tanda PWA, 2026-09-01).
    "6c234f8044ab9ea0bd1fcf9df666409a56b2bdc8ce7069d37835351f4e64197c",
    "17fda7b616215919a140c80176cce36c2852ec9c77b9966e36ab00bdbfd6e052",
];

/// `.mcp.json`: registra el servidor MCP local `synsema-code` (`synsema code --mcp`) para
/// que cualquier agente que abra la carpeta lo descubra solo. Development-time, sobre el
/// código de este proyecto; NO es el MCP que expone la app.
pub const MCP_JSON: &str = r#"{
  "mcpServers": {
    "synsema-code": {
      "command": "synsema",
      "args": ["code", "--mcp"]
    }
  }
}
"#;

/// sha256 de cada contenido histórico de `.mcp.json` (ver `InitFile::past`).
const MCP_JSON_PAST: &[&str] = &[
    // v0.6.13 (a69d6ae): el .mcp.json que introdujo `synsema code` — su sha nunca se
    // agrego a `past` (nacio con la lista vacia; el guard se saltea en CI shallow).
    "add7e6a0fc61c6eb639c5e01ad750e12d32683c305c427f255b2b20884039a39",
];

/// sha256 de cada contenido histórico de `.gitignore` (ver `InitFile::past`).
const GITIGNORE_PAST: &[&str] =
    &["20b449a6499a877f4e5a58d94be5ba3eabf779e2cdfadc1fecf0989a3e9a6314"];

/// Los archivos que `synsema init` genera, en orden.
pub const INIT_FILES: [InitFile; 4] = [
    InitFile { name: "hello.syn", content: HELLO_SYN, past: HELLO_SYN_PAST },
    InitFile { name: ".env.example", content: ENV_EXAMPLE, past: ENV_EXAMPLE_PAST },
    InitFile { name: ".gitignore", content: GITIGNORE, past: GITIGNORE_PAST },
    InitFile { name: ".mcp.json", content: MCP_JSON, past: MCP_JSON_PAST },
];

// =========================================================
// `synsema init --pwa` — app instalable (tanda PWA, specs/pwa-mobile.md)
// =========================================================
//
// Scaffold EMBEBIDO (no descargado, como Synfide): siete archivos de texto que enseñan
// un patrón y se testean contra el motor (regla anti-rot: `app.syn` y `push_keys.syn`
// PARSEAN; el manifest es JSON con íconos 192/512; `index.html` y `sw.js` sólo
// referencian archivos del scaffold o los PNG que init genera desde `icon.svg`).

/// El programa: sitio + manifest + service worker + API + push nativo (opcional).
pub const PWA_APP_SYN: &str = r#"-- Tu app instalable (PWA). Este programa sirve el sitio, el manifest, el service
-- worker y el API. `synsema serve app.syn` → http://localhost:8080 (Chrome y Edge la
-- instalan desde localhost). Producción: `synsema serve app.syn --domain app.example.com
-- --tls-auto you@example.com` (iOS exige HTTPS con certificado confiable).
--
-- Push nativo (opcional): `synsema run push_keys.syn` imprime el par VAPID; pegalo en
-- .env (VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT). Sin eso la página avisa
-- que push no está configurado y todo lo demás funciona igual. ¿Ya tenés OneSignal,
-- FCM u otro proveedor? Llamalo con http_post bajo `require net(...)`; nada te obliga.

require serve(8080)
require time
require file.read("index.html")      -- render() lee la página del disco (en un `synsema build` no hace falta: va dentro del binario)
require env("VAPID_PUBLIC_KEY")
require env("VAPID_SUBJECT")
require secret("VAPID_PRIVATE_KEY")
-- Los push services a los que push_send() habla (deny-by-default: cada host se declara).
-- Chrome/Android → FCM (dos dominios), Edge → WNS, Firefox → Mozilla, Safari/iOS → Apple.
-- Un navegador nuevo = un host nuevo: el error de push_send dice exactamente cuál falta.
require net("fcm.googleapis.com")
require net("jmt17.google.com")
require net("*.notify.windows.com")
require net("updates.push.services.mozilla.com")
require net("web.push.apple.com")

let vapid_public be env("VAPID_PUBLIC_KEY", "")

task vapid_opts()
    give {"vapid": {"public": vapid_public, "private": secret("VAPID_PRIVATE_KEY"), "subject": env("VAPID_SUBJECT", "mailto:you@example.com")}}

serve on 8080
    -- Todo lo estático vive en public/: manifest, service worker, íconos, JS.
    -- Las rutas declaradas ganan sobre el estático; /api/* es lo que la app consume.
    static "/" from "./public" cache "1h"

    route "GET /"
        give render("index.html", {"title": "My app"})

    route "GET /api/ping"
        give ok({"pong": true, "at": now()})

    -- La clave pública VAPID que el navegador necesita para suscribirse ("" = push apagado).
    route "GET /api/push/config"
        give ok({"vapid_public": vapid_public})

    -- El navegador manda su PushSubscription.toJSON(). Acá se guarda en memoria (state_*:
    -- vive lo que el proceso, tope 500 para que nadie la infle). En tu app: guardala en
    -- una tabla, atada al usuario logueado (`requires auth`).
    route "POST /api/push/subscribe"
        rate_limit 10 per minute
        expect body {endpoint: text, keys: map}
        let subs be state_get("push_subs", [])
        let known be false
        each s in subs
            when s["endpoint"] == request.json["endpoint"]
                set known to true
        when not known and length(subs) < 500
            state_set("push_subs", append(subs, request.json))
        give created({"subscriptions": length(state_get("push_subs", []))})

    -- Botón de DEMO: manda una notificación de prueba a todas las suscripciones y olvida
    -- las que el push service reporta como desaparecidas (404/410 → r["gone"]) o las que
    -- ni siquiera se pueden cifrar (claves rotas). En tu app esta ruta lleva
    -- `requires auth`, o el envío vive en un cron/agente y no en una ruta pública.
    route "POST /api/push/test"
        rate_limit 2 per minute
        when vapid_public == ""
            give fail(503, "push is not configured: run `synsema run push_keys.syn` and fill .env")
        let sent be 0
        let kept be []
        each sub in state_get("push_subs", [])
            try
                let r be push_send(sub, {"title": "My app", "body": "Native push from Synsema", "url": "/", "tag": "test"}, vapid_opts())
                when r["ok"]
                    set sent to sent + 1
                when not r["gone"]
                    set kept to append(kept, sub)
            recover err
                -- Sólo se descarta una suscripción ROTA (claves/endpoint inválidos: el error
                -- nombra "subscription"). Un push service no declarado (Capability not granted:
                -- falta un `require net`) o un servicio inalcanzable es config o red del server,
                -- no una suscripción muerta: se conserva y el log dice qué pasó.
                when contains(err, "subscription")
                    log "push dropped (broken subscription): " + err
                otherwise
                    log "push skipped, subscription kept: " + err
                    set kept to append(kept, sub)
        state_set("push_subs", kept)
        give ok({"sent": sent, "kept": length(kept)})
"#;

/// Generador del par VAPID (una vez por app).
pub const PWA_PUSH_KEYS_SYN: &str = r#"-- Genera el par de claves VAPID de tu app (una vez) y lo imprime para pegar en .env.
-- La privada nace sellada (secret): reveal() la muestra a propósito, sólo acá, y deja
-- rastro en el audit (por eso se declara).
require random
require reveal("vapid_private")

let k be push_vapid_keys()
print("VAPID_PUBLIC_KEY=" + k["public"])
print("VAPID_PRIVATE_KEY=" + reveal(k["private"]))
print("VAPID_SUBJECT=mailto:you@example.com")
"#;

/// La página: lo que iOS y Android necesitan para instalar, y nada más.
pub const PWA_INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>{ title }</title>
  <!-- El manifest es lo que hace instalable a la app (ícono, nombre, pantalla completa). -->
  <link rel="manifest" href="/manifest.webmanifest">
  <meta name="theme-color" content="#111111">
  <!-- iOS: sin estas líneas Safari no abre en pantalla completa ni usa tu ícono. -->
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <link rel="icon" href="/icon.svg" type="image/svg+xml">
  <style>{ raw }
    :root { color-scheme: light dark; }
    body { margin: 0; font: 16px/1.5 system-ui, sans-serif;
           padding: max(16px, env(safe-area-inset-top)) 16px max(16px, env(safe-area-inset-bottom)); }
    button { font: inherit; padding: 10px 16px; margin: 4px 8px 4px 0; border-radius: 8px; border: 1px solid #8884; }
    pre { white-space: pre-wrap; word-break: break-word; }
    [hidden] { display: none !important; }
  { end }</style>
</head>
<body>
  <h1>{ title }</h1>
  <p id="status">…</p>
  <button id="install" hidden>Install</button>
  <p id="ios-hint" hidden>On iPhone: Share → Add to Home Screen.</p>
  <button id="ping">Ping the API</button>
  <button id="notify">Notify me</button>
  <button id="test" hidden>Send a test push</button>
  <pre id="out"></pre>
  <script src="/app.js"></script>
</body>
</html>
"##;

/// Manifest (el mismo archivo sirve para instalar en escritorio desde Edge/Chrome).
pub const PWA_MANIFEST: &str = r##"{
  "id": "/",
  "name": "My app",
  "short_name": "My app",
  "description": "An installable app served by Synsema",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#111111",
  "theme_color": "#111111",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any" },
    { "src": "/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ]
}
"##;

/// Service worker: shell offline honesta (nunca cachea /api/ ni respuestas fallidas)
/// + notificaciones push.
pub const PWA_SW_JS: &str = r#"// Service worker de tu app: guarda la "shell" (lo que hace falta para abrir sin red) y
// deja el API en red. Honesto: nunca guarda una respuesta de /api/ ni una que falló —
// una app que muestra datos viejos como nuevos es peor que una que avisa.
// Si tu "/" muestra datos del usuario logueado, sacala de SHELL (cacheá una página
// pública de "sin conexión" en su lugar): el caché es por navegador, no por usuario.
// La shell se sirve "stale-while-revalidate": responde desde el caché y refresca en
// segundo plano, así un cambio se ve en la SIGUIENTE apertura. Para forzarlo en la
// actual, subí CACHE (app-shell-v2): el activate borra el caché viejo.
const CACHE = "app-shell-v1";
const SHELL = ["/", "/app.js", "/manifest.webmanifest", "/icon-192.png", "/badge-96.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/")) {
    // Red o nada: sin server alcanzable el API responde un 503 SINTÉTICO, marcado con
    // X-Synsema-Offline para que la página lo distinga de un 503 real del server.
    e.respondWith(fetch(e.request).catch(() =>
      new Response(JSON.stringify({ error: "offline" }), {
        status: 503, headers: { "Content-Type": "application/json", "X-Synsema-Offline": "1" },
      })
    ));
    return;
  }
  // Shell: lo cacheado responde ya; lo que llega bien por red reemplaza la copia para la
  // próxima vez. El refresh va dentro de waitUntil: sin eso el navegador puede matar el
  // worker apenas respondió y la revalidación se pierde. Sin caché y sin red → error de red.
  const cache = caches.open(CACHE);
  const refresh = fetch(e.request).then(async (res) => {
    if (res.ok) { const c = await cache; await c.put(e.request, res.clone()); }
    return res;
  });
  e.waitUntil(refresh.catch(() => {}));
  e.respondWith(cache.then((c) => c.match(e.request)).then((hit) => hit || refresh.catch(() => Response.error())));
});

// Push: push_send() manda JSON si le pasás un map ({title, body, url, tag}); texto si le
// pasás texto. badge = el ícono monocromo de la barra de estado (Android); tag + renotify =
// un mensaje nuevo con el mismo tag reemplaza al anterior en vez de apilarse.
self.addEventListener("push", (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch (_) { data = { body: e.data ? e.data.text() : "" }; }
  const opts = { body: data.body || "", icon: "/icon-192.png", badge: "/badge-96.png", data };
  if (data.tag) { opts.tag = String(data.tag); opts.renotify = true; }
  e.waitUntil(self.registration.showNotification(data.title || "My app", opts));
});

// Clic en la notificación: enfocar la ventana que ya está abierta (y avisarle qué se tocó)
// en vez de abrir otra instancia sin estado; abrir una nueva sólo si no hay ninguna.
// Si el SO mató la app, la ventana nueva arranca de cero: lo que tenga que sobrevivir
// (borradores, filtros, la vista actual) va a localStorage/IndexedDB, no a variables.
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || "/";
  e.waitUntil(clients.matchAll({ type: "window", includeUncontrolled: true }).then((wins) => {
    const win = wins.find((w) => "focus" in w);
    if (win) {
      win.postMessage({ type: "notificationclick", url, data: e.notification.data });
      return win.focus();
    }
    return clients.openWindow(url);
  }));
});
"#;

/// La parte del navegador: registro del SW, instalar, online/offline, push.
pub const PWA_APP_JS: &str = r#"// La parte del navegador: registra el service worker, ofrece instalar, dice si hay red
// Y si el server responde, y (si el server tiene claves VAPID) pide permiso y se suscribe
// a push.
const $ = (id) => document.getElementById(id);
const say = (t) => { $("out").textContent = t; };
// Un error se muestra ENTERO (nombre + mensaje): "AbortError: Registration failed - push
// service error" dice más que "[object DOMException]".
const explain = (e) => (e && e.name ? e.name + ": " + e.message : String(e));

// 1. Service worker: sin él no hay instalación en Android ni shell offline. El worker avisa
//    por postMessage cuando el usuario toca una notificación con la app ya abierta.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch((e) => say("service worker failed: " + explain(e)));
  navigator.serviceWorker.addEventListener("message", (ev) => {
    if (ev.data && ev.data.type === "notificationclick") {
      say("notification tapped → " + ev.data.url);
      if (ev.data.url && ev.data.url !== location.pathname) location.assign(ev.data.url);
    }
  });
}

// 2. Instalar. Android y escritorio disparan beforeinstallprompt; iOS no tiene API
//    (el usuario usa Compartir → Añadir a pantalla de inicio).
let installEvent = null;
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  installEvent = e;
  $("install").hidden = false;
});
$("install").onclick = async () => {
  if (!installEvent) return;
  installEvent.prompt();
  await installEvent.userChoice;
  installEvent = null;
  $("install").hidden = true;
};
const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
if (isIOS && !standalone) $("ios-hint").hidden = false;

// 3. Estado honesto. navigator.onLine sólo sabe si hay red; que el SERVER responda se
//    prueba con /api/ping sin caché. Con el service worker activo un server caído no llega
//    como error de red sino como el 503 sintético del worker (X-Synsema-Offline: 1): se
//    distingue de un 503 real. Se re-prueba al volver del segundo plano y tras un API fallido.
const status = async () => {
  const where = standalone ? "Installed · " : "";
  if (!navigator.onLine) { $("status").textContent = where + "offline — the shell works, the API does not"; return; }
  try {
    const r = await fetch("/api/ping", { cache: "no-store" });
    if (r.headers.get("X-Synsema-Offline") === "1") $("status").textContent = where + "online, but the server is unreachable";
    else $("status").textContent = where + (r.ok ? "online, server up" : "online, server answered " + r.status);
  } catch (_) {
    $("status").textContent = where + "online, but the server is unreachable";
  }
};
window.addEventListener("online", status);
window.addEventListener("offline", status);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") status(); });
status();

// 4. El API.
$("ping").onclick = async () => {
  try {
    const r = await fetch("/api/ping", { cache: "no-store" });
    say(await r.text());
    if (!r.ok) status();
  } catch (e) { say("offline: " + explain(e)); status(); }
};

// 5. Push: la clave pública VAPID viene del server; la suscripción vuelve al server.
//    En Android el PRIMER subscribe justo después de "Permitir" puede fallar y el segundo
//    andar: se espera al worker ACTIVO (ready puede resolver con uno aún "activating"), se
//    reusa la suscripción si ya existe con la misma clave, y se reintenta con backoff.
function keyBytes(b64url) {
  const s = atob(b64url.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
function sameKey(a, b) {
  const x = new Uint8Array(a), y = new Uint8Array(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}
async function activeWorker() {
  const reg = await navigator.serviceWorker.ready;
  const sw = reg.active || reg.waiting || reg.installing;
  if (!sw || sw.state === "activated") return reg;
  // Esperar al worker ACTIVO, con tope: si un sw.js nuevo lo reemplazó ("redundant") o no
  // activa en 10 s, no se cuelga el botón — se vuelve a pedir `ready` o se explica.
  await new Promise((ok, fail) => {
    const timer = setTimeout(() => fail(new Error("the service worker did not activate in 10 s — reload the page and try again")), 10000);
    sw.addEventListener("statechange", () => {
      if (sw.state === "activated" || sw.state === "redundant") { clearTimeout(timer); ok(); }
    });
  });
  return navigator.serviceWorker.ready;
}
async function subscribe(reg, key) {
  const existing = await reg.pushManager.getSubscription();
  if (existing) {
    const cur = existing.options && existing.options.applicationServerKey;
    if (!cur || sameKey(cur, keyBytes(key).buffer)) return existing;
    await existing.unsubscribe();               // el server rotó la clave VAPID: la vieja no sirve
  }
  let last;
  for (let i = 0; i < 3; i++) {
    try {
      return await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(key) });
    } catch (e) {
      last = e;
      await new Promise((ok) => setTimeout(ok, 500 * (i + 1)));
    }
  }
  throw last;
}
$("notify").onclick = async () => {
  try {
    const cfg = await (await fetch("/api/push/config", { cache: "no-store" })).json();
    if (!cfg.vapid_public) return say("push is not configured on the server (see app.syn)");
    if (!("PushManager" in window)) {
      return say(isIOS && !standalone
        ? "iOS: install the app first (Share → Add to Home Screen), then tap again"
        : "this browser has no Web Push");
    }
    if (Notification.permission === "denied") return say("notifications are blocked for this site — allow them in the browser settings");
    if (Notification.permission !== "granted" && (await Notification.requestPermission()) !== "granted") return say("notifications denied");
    const reg = await activeWorker();
    const sub = await subscribe(reg, cfg.vapid_public);
    const r = await fetch("/api/push/subscribe", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(sub.toJSON()),
    });
    say("subscribed: " + (await r.text()));
    $("test").hidden = false;
  } catch (e) { say("push failed: " + explain(e)); }
};
$("test").onclick = async () => {
  try {
    const r = await fetch("/api/push/test", { method: "POST" });
    say(await r.text());
  } catch (e) { say("test failed: " + explain(e)); }
};
"#;

/// Ícono fuente. Editalo y volvé a correr `synsema init --pwa`: los PNG se regeneran.
pub const PWA_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <!-- Editá este archivo y volvé a correr el init con el flag pwa: regenera icon-192.png,
       icon-512.png y apple-touch-icon.png. Zona segura para íconos "maskable": el 80% central. -->
  <rect width="512" height="512" rx="96" fill="#111111"/>
  <circle cx="256" cy="256" r="150" fill="none" stroke="#f5f5f5" stroke-width="28"/>
  <circle cx="256" cy="256" r="52" fill="#f5f5f5"/>
</svg>
"##;

/// Ícono "maskable" (Android recorta la forma): fondo a lienzo completo, dibujo en el 80% central.
pub const PWA_ICON_MASKABLE_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <!-- Ícono "maskable" (Android recorta la forma: círculo, gota, cuadrado redondeado). El
       fondo llena TODO el lienzo y el dibujo queda en el 80% central, la zona segura.
       Editalo y volvé a correr el init con el flag pwa: regenera icon-maskable-512.png. -->
  <rect width="512" height="512" fill="#111111"/>
  <circle cx="256" cy="256" r="150" fill="none" stroke="#f5f5f5" stroke-width="28"/>
  <circle cx="256" cy="256" r="52" fill="#f5f5f5"/>
</svg>
"##;

/// Badge monocromo de la barra de estado (Android); el sistema lo tiñe.
pub const PWA_BADGE_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <!-- Badge: el ícono MONOCROMO de la barra de estado de Android (blanco sobre transparente;
       el sistema lo tiñe). Sin él, Android muestra un ícono genérico. Editalo y volvé a correr
       el init con el flag pwa: regenera badge-96.png. -->
  <circle cx="256" cy="256" r="150" fill="none" stroke="#ffffff" stroke-width="40"/>
  <circle cx="256" cy="256" r="60" fill="#ffffff"/>
</svg>
"##;

/// Los archivos de `synsema init --pwa`, en orden (el scaffold base va aparte, sin
/// `hello.syn`: acá el starter es `app.syn`). Los PNG NO están en la lista: son
/// derivados de `icon.svg` y los genera `cmd_init` (ver `pwa_icons`).
pub const PWA_FILES: [InitFile; 9] = [
    // `past`: los sha256 (forma LF) de cada versión publicada — v0.6.15 fue la primera.
    InitFile { name: "app.syn", content: PWA_APP_SYN, past: &[
        "b35f3e66902c4380aececfcf717025d97f475d8f76226e0f345fc1266c5ec2ef", // v0.6.15
        "c871f31d0cebbda647c7020ce3416ec3b9f25f452cf7ab0c0574ef756859afe4", // v0.6.16
    ] },
    InitFile { name: "push_keys.syn", content: PWA_PUSH_KEYS_SYN, past: &[] },
    InitFile { name: "index.html", content: PWA_INDEX_HTML, past: &[] },
    InitFile { name: "public/manifest.webmanifest", content: PWA_MANIFEST, past: &["c48e191fff4cd83fb8231658dc88ad185abfb592d9614c1cb3983345bfe684ad"] },
    InitFile { name: "public/sw.js", content: PWA_SW_JS, past: &[
        "4aa649614a3aa18b32c2b16668b467be1c46220ff3f39e9c5bcd1bb70fbf64c1", // v0.6.15
        "d8ea3c6b66672616782530e81c3075d9329dcc3e1824cdcff6bb6db97c5f117f", // v0.6.16
    ] },
    InitFile { name: "public/app.js", content: PWA_APP_JS, past: &[
        "94335092a403265f2e954afc1c2d80ad254e343c1c3cffae23dd3521244d1314", // v0.6.15
        "c6322257eb20df92ef0d615ea04238de16f11566d6ee6e64971afe669436646f", // v0.6.16
    ] },
    InitFile { name: "public/icon.svg", content: PWA_ICON_SVG, past: &[] },
    InitFile { name: "public/icon-maskable.svg", content: PWA_ICON_MASKABLE_SVG, past: &[] },
    InitFile { name: "public/badge.svg", content: PWA_BADGE_SVG, past: &[] },
];

/// Los SVG fuente del scaffold (ruta, contenido de fábrica): `init` sabe si el usuario los editó.
pub const PWA_ICON_SOURCES: [(&str, &str); 3] = [
    ("public/icon.svg", PWA_ICON_SVG),
    ("public/icon-maskable.svg", PWA_ICON_MASKABLE_SVG),
    ("public/badge.svg", PWA_BADGE_SVG),
];

/// Los PNG que init deriva de los SVG: (SVG fuente, PNG, lado en px). 192/512 `any` +
/// apple-touch-icon desde `icon.svg`; el `maskable` desde su propio SVG (fondo a lienzo
/// completo); el badge monocromo de Android desde `badge.svg`.
pub const PWA_ICONS: [(&str, &str, u32); 5] = [
    ("public/icon.svg", "public/icon-192.png", 192),
    ("public/icon.svg", "public/icon-512.png", 512),
    ("public/icon.svg", "public/apple-touch-icon.png", 180),
    ("public/icon-maskable.svg", "public/icon-maskable-512.png", 512),
    ("public/badge.svg", "public/badge-96.png", 96),
];

/// Nombre de la constante que guarda cada archivo (para el guard de historia).
#[cfg(test)]
pub fn const_name(file: &str) -> &'static str {
    match file {
        "hello.syn" => "HELLO_SYN",
        ".env.example" => "ENV_EXAMPLE",
        ".mcp.json" => "MCP_JSON",
        ".gitignore" => "GITIGNORE",
        "app.syn" => "PWA_APP_SYN",
        "push_keys.syn" => "PWA_PUSH_KEYS_SYN",
        "index.html" => "PWA_INDEX_HTML",
        "public/manifest.webmanifest" => "PWA_MANIFEST",
        "public/sw.js" => "PWA_SW_JS",
        "public/app.js" => "PWA_APP_JS",
        "public/icon.svg" => "PWA_ICON_SVG",
        "public/icon-maskable.svg" => "PWA_ICON_MASKABLE_SVG",
        "public/badge.svg" => "PWA_BADGE_SVG",
        other => panic!("init_templates: no constant registered for '{}'", other),
    }
}

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
        for f in INIT_FILES.iter().chain(PWA_FILES.iter()) {
            // Un template con `"#` adentro (colores CSS) vive en `r##"…"##`; los demás
            // en `r#"…"#`. Se aceptan las dos formas (y un template puede cambiar de una
            // a otra sin perder su historia).
            let markers = [
                (format!("pub const {}: &str = r##\"", const_name(f.name)), "\"##;"),
                (format!("pub const {}: &str = r#\"", const_name(f.name)), "\"#;"),
            ];
            let current = sha256_of(f.content);
            let mut missing: Vec<String> = Vec::new();
            for c in log.split_whitespace() {
                let Some(src) = git(&["show", &format!("{}:{}", c, rel)]) else { continue };
                let Some((i, marker, close)) = markers
                    .iter()
                    .find_map(|(m, close)| src.find(m.as_str()).map(|i| (i, m, *close)))
                else {
                    continue;
                };
                let body = &src[i + marker.len()..];
                let Some(j) = body.find(close) else { continue };
                // rustc normaliza CRLF → LF dentro de TODO literal (raw incluido): lo que
                // el binario escribe en disco es la forma LF. Se hashea esa forma, así el
                // sha corresponde a un archivo que un proyecto real puede tener, sin
                // importar con qué finales de línea quedó commiteado el fuente.
                let h = sha256_of(&body[..j].replace("\r\n", "\n"));
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
        for f in INIT_FILES.iter().chain(PWA_FILES.iter()) {
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

    // Anti-rot (PWA): los programas del scaffold PARSEAN con el parser real.
    #[test]
    fn pwa_programs_parse() {
        for (name, src) in [("app.syn", PWA_APP_SYN), ("push_keys.syn", PWA_PUSH_KEYS_SYN)] {
            if let Err(e) = synsema_core::parser::parse_source(src, name) {
                panic!("el template {} NO parsea: {:?}", name, e);
            }
        }
    }

    /// Anti-rot (PWA): el manifest es JSON con los dos íconos que Android/Chrome exigen
    /// para instalar (192 y 512), start_url/scope raíz y display standalone; y cada ícono
    /// que nombra lo genera init.
    #[test]
    fn pwa_manifest_is_installable() {
        let m: serde_json::Value = serde_json::from_str(PWA_MANIFEST).expect("manifest JSON");
        assert_eq!(m["start_url"], "/");
        assert_eq!(m["scope"], "/");
        assert_eq!(m["display"], "standalone");
        assert_eq!(m["id"], "/", "un id estable: la app sigue siendo la misma si cambia start_url");
        let icons = m["icons"].as_array().expect("icons");
        let sizes: Vec<&str> = icons.iter().map(|i| i["sizes"].as_str().unwrap()).collect();
        assert!(sizes.contains(&"192x192") && sizes.contains(&"512x512"), "{:?}", sizes);
        // `any` y `maskable` van en íconos DISTINTOS (Lighthouse desaconseja "any maskable" combinado).
        let purposes: Vec<&str> = icons.iter().map(|i| i["purpose"].as_str().unwrap_or("any")).collect();
        assert!(purposes.contains(&"maskable") && !purposes.iter().any(|p| p.contains(' ')), "{:?}", purposes);
        for i in icons {
            let src = i["src"].as_str().unwrap().trim_start_matches('/');
            assert!(
                PWA_ICONS.iter().any(|(_, n, _)| n.trim_start_matches("public/") == src),
                "el ícono {} no lo genera init",
                src
            );
        }
    }

    /// Anti-rot (PWA): index.html, sw.js, app.js y el manifest sólo referencian rutas que
    /// el scaffold escribe o que init genera — un 404 en la shell rompe la instalación.
    #[test]
    fn pwa_scaffold_references_are_closed() {
        let served: Vec<String> = PWA_FILES
            .iter()
            .filter_map(|f| f.name.strip_prefix("public/").map(|s| format!("/{}", s)))
            .chain(PWA_ICONS.iter().map(|(_, n, _)| format!("/{}", n.trim_start_matches("public/"))))
            .chain(["/".to_string()])
            .collect();
        for text in [PWA_INDEX_HTML, PWA_SW_JS, PWA_APP_JS, PWA_MANIFEST] {
            for part in text.split('"') {
                // Una ruta local de la shell: "/x.ext" o "/" (el API queda fuera: es red).
                let is_local_path = part.starts_with('/')
                    && !part.starts_with("/api/")
                    && !part.contains(' ')
                    && part.matches('/').count() == 1;
                if is_local_path {
                    assert!(served.contains(&part.to_string()), "{} se referencia pero el scaffold no lo sirve", part);
                }
            }
        }
    }

    /// Anti-rot (PWA): el SVG del ícono rasteriza a los tres tamaños que init escribe.
    #[test]
    fn pwa_icon_svg_rasterizes() {
        for (src, _, px) in PWA_ICONS {
            let svg = PWA_ICON_SOURCES.iter().find(|(p, _)| *p == src).map(|(_, c)| *c).expect("source svg");
            let png = synsema_stdlib::raster::render_svg_png(svg, px, px).expect("render");
            assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
            let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
            let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
            assert_eq!((w, h), (px, px));
        }
    }

    /// Anti-rot (PWA): `.webmanifest` tiene content-type pinneado (lo que hace que el
    /// navegador acepte el manifest sin depender del registro del host).
    #[test]
    fn pwa_manifest_content_type_is_pinned() {
        assert_eq!(
            synsema_stdlib::server::web_content_type(".webmanifest"),
            Some("application/manifest+json")
        );
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
            .chain(synsema_runtime::run_program::RUN_PROGRAM_ENV_VARS.iter())
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

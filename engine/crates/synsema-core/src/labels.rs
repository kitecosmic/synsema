//! Etiquetas de flujo de información por principal (`private` / `declassify`, T5).
//!
//! `secret` dice "esto no se lee"; `private` dice "esto se computa pero sólo sale a
//! quien corresponde". Una etiqueta es un **conjunto de principales** (no un bit):
//! `private(v, "bank")` etiqueta con `{bank}`; el join de dos valores es la **unión**;
//! público es el conjunto vacío. Un sumidero declara a quién acepta y un valor fluye si
//! su etiqueta ⊆ lo aceptado (`check_flow`). Las fuentes y los sumideros los pone el
//! HOST (el adaptador de la plataforma, `serve --attested`): el motor sólo propaga y
//! ofrece la API de este módulo para marcar (`mark`) y comprobar (`check_flow`,
//! `strip_deep`).
//!
//! Representación: `SynValue::Private(Rc<Labelled>)`, una **variante aislada** del enum
//! (mismo argumento que `secret`, ver `secret.rs`): no es un bit de taint en todos los
//! valores. Con las etiquetas apagadas (`Interpreter::set_labels(false)`, el default) la
//! variante no se construye nunca y el intérprete no ejecuta ningún camino nuevo más allá
//! de un `if self.labels`: coste cero.
//!
//! Invariantes de la variante (los garantiza `mark`):
//!   * nunca `Private` de `Private` (marcar uno existente = unión de etiquetas);
//!   * nunca `Private` con etiqueta vacía (= el valor pelado);
//!   * nunca `Private` de un `Secret` (un secret ya es opaco; el intérprete lo rechaza
//!     con "a secret is already opaque; use private on the value you compute"; `mark`
//!     devuelve el secret intacto).
//!
//! Qué cubre la propagación del intérprete (sólo con etiquetas encendidas):
//!   * **flujos explícitos**: operadores binarios y unarios (con la etiqueta PROFUNDA de los
//!     operandos: `{"k": private(1)} == {"k": 1}` sale privado), índice/campo (leer un campo
//!     de un mapa privado da un valor privado), iteración, y el despacho genérico de
//!     builtins (los argumentos se pasan sin etiquetas y el resultado sale con la unión
//!     de las etiquetas profundas de todos los argumentos ∪ la etiqueta de PC);
//!   * **flujos implícitos** (etiqueta de PC): si la condición de `when`/`otherwise when`/
//!     `while`/`each`, el sujeto de un `match`, un patrón o un guard llevan etiquetas (a
//!     cualquier profundidad), el cuerpo corre bajo esa unión; los binders, el valor
//!     IMPLÍCITO del bloque (la última expresión sin `give`) y todo `give` salen con el PC;
//!     todo literal ESCALAR evaluado bajo PC lleva el PC (qué literal se evaluó depende de la
//!     rama; los literales List/Map no se envuelven: sus elementos ya llevan lo suyo). Un
//!     builtin que recibe argumentos privados también corre bajo PC (sus callbacks heredan
//!     la etiqueta);
//!   * **un salto de control desde un contexto privado no se puede observar** (ronda 2):
//!     un error o `raise` que NACE con PC no vacío queda marcado (`RuntimeError::
//!     from_private_pc`) y **no es atrapable** — ni `try/recover` ni `assert_error` lo
//!     recuperan: se propaga hasta el host (en un guest, una request fallida con código
//!     uniforme). Atraparlo hacía del enforcement el canal: un bit público por iteración
//!     alcanzaba para extraer el valor entero. Lo mismo vale para el veredicto del propio
//!     sistema (`from_labels`).
//!
//!     **La tinta va en la RAMA, no en el salto** (ronda 3): al evaluar un `when`/`match`/bucle
//!     con condición privada cuyo cuerpo puede salir antes de tiempo (`give`/`stop`/`raise`,
//!     decidido estáticamente sobre el AST), la continuación queda teñida ahí mismo, **se tome
//!     o no la rama**. Teñir cuando el salto dispara llegaba tarde: para entonces las vueltas
//!     anteriores del bucle ya habían escrito el estado público con PC vacío y el secreto ya
//!     estaba en la variable. Con la tinta en la rama, el `set counter to counter + 1` de la
//!     vuelta 0 ya viola y la corrida falla cerrada. Un `stop` ejecutado bajo PC privado **tiñe
//!     la continuación**
//!     (`control_taint`, unida al PC en `pc_label()`): cuántas vueltas alcanzó a dar el bucle
//!     es información privada que quedaría en variables públicas escritas ANTES del salto y se
//!     leería después. Ese residuo es ACOTADO: vale hasta el final del bloque/bucle y del resto
//!     del cuerpo de la task donde saltó, y se limpia siempre al volver de una task, al
//!     terminar un bloque `test`, un request o la unidad de ejecución, también por el camino de
//!     error. Un `give` **no** tiñe a nadie: su punto de llegada es el sitio de la llamada, que
//!     es un join point, y lo que transporta la información es el VALOR devuelto, que ya sale
//!     con el PC (B2). El cuerpo de un `recover` corre bajo `PC ∪ etiqueta de lo privado tocado
//!     dentro del `try``;
//!   * **no-sensitive-upgrade ESTRICTO**: asignar bajo PC (`set` a variable, índice o campo;
//!     `let`/`task` que re-ligan un nombre ya existente en el mismo scope) a algo cuya
//!     etiqueta efectiva no cubre el PC es `label_violation` — nunca "se convierte" la
//!     variable (la conversión permisiva permite extraer un valor entero probando ramas:
//!     Austin–Flanagan). Una variable/contenedor ya privados que cubren el PC siguen
//!     funcionando (`set state["balances"][to] to x` con `state` y `to` en {app}); un `let`
//!     nuevo nace privado. Un `Secret` bajo PC es error (no se etiqueta y `reveal` lavaría).
//!     La etiqueta que se compara en un camino (`set m["a"]["b"]`) es la del **binding raíz**,
//!     no la del contenedor intermedio recién evaluado: si no, un índice literal marcado por
//!     el PC inflaba la etiqueta del intermedio y la comprobación se cumplía sola;
//!   * **el PC no asciende contenedores**: `pc_mark` sólo envuelve escalares (los de adentro
//!     ya llevan el PC y `label_deep` los ve). Envolver un contenedor con el PC fabricaba un
//!     envoltorio privado sobre el mismo `Rc` que una variable pública. Por eso el builtin
//!     `private(v, p)` usa `mark_owned`, que **copia** el contenedor antes de envolverlo;
//!   * **el metadato de etiqueta es público**: el principal de `private` y el destino de
//!     `declassify` tienen que ser un **literal escrito en esa llamada** (el motivo, un literal
//!     o un valor sin etiquetas). El nombre de un principal se imprime verbatim en los
//!     diagnósticos `label_violation`, que son el único canal que NUNCA se redacta y que bajo
//!     `serve` llegan al cliente: una variable pública con texto arbitrario ahí era un canal de
//!     exfiltración. Los principales que el HOST usa para etiquetar sus fuentes se declaran con
//!     `Interpreter::register_label_principal` para que salgan por nombre; cualquier otro se
//!     imprime como `#<índice>`. `label_of(v)` e `is_private(v)` devuelven su resultado marcado
//!     con `label_deep(v) ∪ PC`: si no, son oráculos;
//!   * **auditar un programa con etiquetas** no se hace con `label_of`/`is_private` (usarlos
//!     para DECIDIR es una violación, justamente porque describen datos privados). El camino es:
//!     `codeintel::declassify_sites` / `synsema code check` para el listado estático de cada
//!     sitio de `declassify` con su motivo, destino y `constant`, y `Interpreter::declassify_log`
//!     para lo que la corrida liberó de verdad (motivo, `from`, `to`, ubicación). Los dos se
//!     cruzan: el estático puede no ver un alias indirecto (`declassify_static_only`) y el de
//!     runtime sólo ve lo que se ejecutó;
//!   * **escape explícito**: cuando el lado derecho de un `let`, `set` (a variable, índice
//!     o campo) o `give` es SINTÁCTICAMENTE `declassify(...)` (resuelto al builtin), el valor
//!     asignado/devuelto queda con la etiqueta que `declassify` devolvió (su `to`) y NO se le
//!     une la del PC (tampoco se exige que el destino cubra el PC). Justificación: un handler
//!     entero suele correr bajo un `match` sobre datos privados (PC ≠ ∅ en todo el cuerpo) y
//!     sin esta regla ningún resultado podría publicarse jamás; `declassify` es la ÚNICA vía
//!     de escape, el programador la escribe en ese sitio concreto, `declassify` registra el
//!     origen REAL (`from = etiqueta profunda del valor ∪ PC`, así declassificar un literal
//!     dentro de una rama privada queda como `from [app] to []`) y
//!     `codeintel::declassify_sites` lista cada sitio con motivo, destino y `constant` (el
//!     argumento es un literal: declassificación pura de PC) para el auditor. El principal de
//!     `private` y el motivo/destino de `declassify` tienen que ser públicos. Un `let x be r`
//!     posterior bajo PC sí re-etiqueta; `give {"a": declassify(...)}` envuelve el mapa entero
//!     con el PC (sólo el elemento inline queda con la etiqueta declarada);
//!   * **sumideros**: un builtin registrado con `Interpreter::register_label_sink` (los del
//!     core en `CORE_SINK_BUILTINS`; el host registra fs/http/sql/ws/memory/env/exec/
//!     blackboard/llm/webpush/run/proc) y las sentencias con efecto (`share`/`signal`/`send`/
//!     `spawn`/`approve`/`confirm`/`ask`/`reason`/`decide`/`analyze`/`generate`) exigen, ANTES
//!     de correr, argumentos sin etiquetas (profundo, con el camino en el error) y PC vacío;
//!   * **nombres protegidos**: `private`/`declassify`/`label_of`/`is_private`/`print` no se
//!     pueden redefinir ni sombrear (task, `let`, parámetro, alias…): error de carga, **con
//!     etiquetas apagadas también**. Es deliberado y es un cambio incompatible de la
//!     superficie del lenguaje (va al CHANGELOG): las etiquetas de TODO el programa las
//!     deciden esos cinco builtins, el mismo programa puede cargarlo un host que las encienda,
//!     y el chequeo sintáctico que distingue un `declassify(...)` real del de una task del
//!     programa depende de que el nombre no se pueda sombrear;
//!   * el mensaje de un error atrapado por `try/recover` sale etiquetado con todo lo que
//!     se desenvolvió o gateó control dentro del `try` (aproximación conservadora); un error
//!     NO atrapado que sale hacia el host se REDACTA (`private(<labels>)`) si **nació** bajo
//!     PC privado — por el flag del error, no por el `seen` monótono de la corrida ni por el
//!     TEXTO del mensaje (un `raise "label_violation: …"` del programa no puede hacerse pasar
//!     por un diagnóstico del sistema). La ubicación `file:line:col` se conserva siempre.
//!
//! Qué NO cubre (documentado, no se promete):
//!   * **terminación**: error vs éxito, y por lo tanto 1 bit por corrida. Una violación de
//!     NSU mata la corrida y eso es observable desde afuera (en un guest sale como
//!     `runtime_error`); también lo es cuántas líneas imprime una rama;
//!   * **tiempo**;
//!   * **`steps()`**: es un canal PÚBLICO — dos ramas privadas cuentan distinto y el contador
//!     sigue siendo legible. Sale con la etiqueta del PC del sitio donde se lo llama (no con
//!     todo lo que la corrida tocó: eso envenenaba la instrumentación de cualquier programa).
//!     Un host que mida `steps` y lo publique está publicando ese canal;
//!   * **la FORMA de un literal List/Map** construido en una rama (sus claves son texto del
//!     programa; sus valores sí llevan el PC);
//!   * **estado público escrito ANTES de un `stop`, leído fuera de la task donde saltó**: el
//!     residuo de control se limpia en el borde de la task (si no, un `give` normal dejaba PC
//!     sobre código enteramente público del llamador y rompía programas sanos), así que un
//!     `stop` privado dentro de una task que ya incrementó una variable GLOBAL pública deja
//!     ese contador legible por el llamador. Dentro de la task sí está cubierto;
//!   * **`when` no abre scope**: un `let` nuevo dentro de una rama sigue visible después del
//!     `when`, así que la EXISTENCIA del binding es estado público que depende de la rama
//!     (su VALOR sí lleva el PC, y usarlo propaga la etiqueta). Es semántica del lenguaje
//!     anterior a las etiquetas —`when` comparte el entorno del bloque, a diferencia de
//!     `each`/`match`, y los programas del repo lo usan así— y cambiarla sería incompatible
//!     mucho más allá del modo TEE; queda como límite conocido.
//!
//! Los sumideros de I/O que el host no registre tampoco se comprueban: el host tiene
//! `check_flow`, `strip_deep` e `Interpreter::pc_label` para hacerlo en su borde.

use std::fmt;
use std::rc::Rc;

use indexmap::IndexMap;

use crate::tokens::SourceLocation;
use crate::types::{syn_list, syn_map, ServerValue, SynValue};

/// Conjunto de principales, SIEMPRE ordenado y sin duplicados (lo normaliza
/// `label_from`; `union` y `reduce` preservan el orden). El conjunto vacío = público.
pub type Label = Rc<[Rc<str>]>;

/// Payload de `SynValue::Private`: el valor computable + su etiqueta (no vacía).
pub struct Labelled {
    pub value: SynValue,
    pub label: Label,
}

/// Entrada del registro de `declassify` (una por llamada ejecutada): motivo, etiqueta de
/// origen, etiqueta destino y ubicación en el fuente. El host lo lee con
/// `Interpreter::declassify_log`.
#[derive(Clone, Debug)]
pub struct DeclassifyEntry {
    pub reason: String,
    pub from: Label,
    pub to: Label,
    pub loc: SourceLocation,
}

/// Un valor privado llegó a un sumidero que no acepta (todos) sus principales.
#[derive(Clone, Debug)]
pub struct LabelViolation {
    /// Camino hasta el valor ofensor, p. ej. `events[0].data.amount`.
    pub path: String,
    /// Etiqueta efectiva del valor (unión de las etiquetas que lo envuelven).
    pub label: Label,
    /// Lo que el sumidero acepta (vacío = público).
    pub accepted: Label,
}

impl fmt::Display for LabelViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Toda la familia `label_violation:` termina en un REMEDIO concreto (era el único
        // mensaje que no lo traía y el host se lo agregaba por fuera). Acá el remedio enseña
        // además el patrón sano para un contenedor: `declassify` de un mapa entero es un
        // `strip_deep` que publica todo lo anidado — hay que declassificar el escalar que se
        // quiere publicar y armar el contenedor afuera de la rama privada.
        write!(
            f,
            "label_violation: {} is private to {}, the sink accepts {}; declassify(<that value>, \"<why it may be published>\") the scalar you want to publish and build the container outside the private branch",
            self.path,
            // T5 (ronda 8): los principales DECLARADOS, no los de ESTE valor. Este `Display` es
            // el que el chequeo de la respuesta HTTP manda al cliente remoto — el único camino
            // que importa en un despliegue atestado, y el que quedó abierto en la ronda 7.
            principals_out(),
            // `accepted` es lo que el SUMIDERO declara aceptar (una propiedad estática del
            // sumidero, no del valor), así que se imprime tal cual.
            if self.accepted.is_empty() { "(public)".to_string() } else { label_display_raw(&self.accepted) }
        )
    }
}

impl std::error::Error for LabelViolation {}

/// Etiqueta vacía (público).
pub fn empty() -> Label {
    Rc::from(Vec::<Rc<str>>::new())
}

/// Construye una etiqueta normalizada (ordenada, sin duplicados, sin nombres vacíos).
pub fn label_from<S: AsRef<str>>(names: &[S]) -> Label {
    let mut v: Vec<Rc<str>> = names
        .iter()
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .map(Rc::from)
        .collect();
    v.sort();
    v.dedup();
    Rc::from(v)
}

/// `a,b` (para la redacción `private(a,b)` y los mensajes).
/// Los principales de una etiqueta, TAL CUAL.
///
/// ⚠️ T5 (ronda 8) — **jamás en un texto que salga del proceso.** Esa lista depende de qué valor
/// se selecciono, asi que imprimirla publica el dato que la etiqueta protege: es el canal que la
/// ronda 7 cerró en dos embudos y que la ronda 8 volvió a encontrar por el tercero (la respuesta
/// HTTP). Para cualquier mensaje hacia afuera está `redacted_display()` / `principals_out()`, que
/// imprimen el conjunto DECLARADO, constante. Esto queda para comparaciones internas y tests, y
/// se llama `_raw` justamente para que un sitio nuevo tenga que elegirlo a propósito.
pub fn label_display_raw(l: &Label) -> String {
    l.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(",")
}

thread_local! {
    /// T5 (ronda 7) — el texto con el que se REDACTA, fijado por el intérprete al cargar el
    /// programa: el conjunto de principales que el fuente declara (más los que registra el
    /// host), que es constante para la corrida. Nunca la etiqueta del valor concreto: esa varía
    /// con qué valor se seleccionó, y por ahí salía el dato entero (`private(app,p0)` vs
    /// `private(app,p1)` según el índice privado). Vive acá porque el `Display` de un valor
    /// privado no tiene manera de alcanzar al intérprete.
    static REDACTION_TEXT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Respaldo por PROCESO. El `serve` atiende en hilos worker cuyo intérprete se construye ahí, y
/// el recorrido estático del programa lo hizo el hilo principal: sin esto el mensaje que va al
/// cliente decía `private(…)` en vez de `private(app)`. Hay un programa por proceso, así que el
/// conjunto es el mismo para todos; el thread-local sigue mandando para que dos tests en paralelo
/// (cada uno con su programa) no se pisen.
static REDACTION_FALLBACK: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// Fija el texto de redacción de este hilo (y el respaldo del proceso). Idempotente.
pub fn set_redaction_text(text: &str) {
    REDACTION_TEXT.with(|t| {
        let mut t = t.borrow_mut();
        if *t != text {
            t.clear();
            t.push_str(text);
        }
    });
    if !text.is_empty() {
        if let Ok(mut g) = REDACTION_FALLBACK.write() {
            if *g != text {
                g.clear();
                g.push_str(text);
            }
        }
    }
}

/// El texto efectivo: el de este hilo, o el del proceso si este hilo no lo tiene.
fn redaction_text() -> String {
    let local = REDACTION_TEXT.with(|t| t.borrow().clone());
    if !local.is_empty() {
        return local;
    }
    REDACTION_FALLBACK.read().map(|g| g.clone()).unwrap_or_default()
}

/// Los principales DECLARADOS, para un mensaje que sale del proceso. `…` si no hay ninguno.
/// **Éste es el embudo**: todo texto hacia afuera que quiera nombrar principales pasa por acá o
/// por `redacted_display()`, nunca por `label_display_raw`.
pub fn principals_out() -> String {
    let t = redaction_text();
    if t.is_empty() {
        "…".to_string()
    } else {
        t
    }
}

/// Cómo se imprime un valor privado: `private(app)` con los principales DECLARADOS, o
/// `private(…)` si el programa no declaró ninguno (por ejemplo cuando el host marcó las fuentes
/// y todavía no se registraron). Constante para la corrida — ver `REDACTION_TEXT`.
pub fn redacted_display() -> String {
    let t = redaction_text();
    if t.is_empty() {
        "private(…)".to_string()
    } else {
        format!("private({})", t)
    }
}

/// Unión de dos etiquetas (merge de listas ordenadas). Reusa el `Rc` cuando una contiene
/// a la otra: el caso común (misma etiqueta a ambos lados) no aloca.
pub fn union(a: &Label, b: &Label) -> Label {
    if a.is_empty() || subset(a, b) {
        return b.clone();
    }
    if b.is_empty() || subset(b, a) {
        return a.clone();
    }
    let mut out: Vec<Rc<str>> = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                out.push(a[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(b[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                out.push(a[i].clone());
                i += 1;
                j += 1;
            }
        }
    }
    out.extend(a[i..].iter().cloned());
    out.extend(b[j..].iter().cloned());
    Rc::from(out)
}

/// Diferencia `a \ b` (ambas ordenadas): los principales de `a` que no están en `b`. La usa
/// el intérprete para saber qué privados se tocaron evaluando UN nodo (el delta de `seen`),
/// en vez de arrastrar el acumulado de toda la corrida.
pub fn difference(a: &Label, b: &Label) -> Label {
    if b.is_empty() {
        return a.clone();
    }
    let mut out: Vec<Rc<str>> = Vec::new();
    let mut j = 0;
    for x in a.iter() {
        while j < b.len() && b[j].as_ref() < x.as_ref() {
            j += 1;
        }
        if j < b.len() && b[j].as_ref() == x.as_ref() {
            continue;
        }
        out.push(x.clone());
    }
    if out.len() == a.len() {
        return a.clone();
    }
    Rc::from(out)
}

/// ¿`a ⊆ b`? (ambas ordenadas). La vacía es subconjunto de todo.
pub fn subset(a: &Label, b: &Label) -> bool {
    let mut j = 0;
    for x in a.iter() {
        while j < b.len() && b[j].as_ref() < x.as_ref() {
            j += 1;
        }
        if j >= b.len() || b[j].as_ref() != x.as_ref() {
            return false;
        }
        j += 1;
    }
    true
}

/// Etiqueta SUPERFICIAL: la del `Private` de arriba, o vacía.
#[inline]
pub fn label(v: &SynValue) -> Label {
    match v {
        SynValue::Private(p) => p.label.clone(),
        _ => empty(),
    }
}

/// Etiqueta PROFUNDA: unión de todas las etiquetas dentro de listas, mapas y valores del
/// servidor. Es lo que un sumidero o un builtin ven "de verdad" en el valor.
pub fn label_deep(v: &SynValue) -> Label {
    let mut acc = empty();
    deep_into(v, &mut acc);
    acc
}

fn deep_into(v: &SynValue, acc: &mut Label) {
    match v {
        SynValue::Private(p) => {
            *acc = union(acc, &p.label);
            deep_into(&p.value, acc);
        }
        SynValue::List(l) => {
            for x in l.borrow().iter() {
                deep_into(x, acc);
            }
        }
        SynValue::Map(m) => {
            for x in m.borrow().values() {
                deep_into(x, acc);
            }
        }
        SynValue::Server(s) => match &**s {
            ServerValue::Envelope { value, .. } => deep_into(value, acc),
            ServerValue::Node(m) => {
                for x in m.borrow().values() {
                    deep_into(x, acc);
                }
            }
            ServerValue::Content(inner) => deep_into(inner, acc),
            ServerValue::WithHeaders { inner, .. } => deep_into(inner, acc),
            ServerValue::Raw { .. }
            | ServerValue::RawBytes { .. }
            | ServerValue::Redirect { .. }
            | ServerValue::Paged(_) => {}
        },
        _ => {}
    }
}

/// ¿Hay alguna etiqueta en el valor (a cualquier profundidad)?
pub fn has_label_deep(v: &SynValue) -> bool {
    !label_deep(v).is_empty()
}

/// Envuelve `v` con `label` (o une, si `v` ya es privado). Etiqueta vacía → devuelve `v`
/// pelado. Un `Secret` se devuelve intacto (ya es opaco; el intérprete rechaza la mezcla
/// antes de llegar acá).
pub fn mark(v: SynValue, label: Label) -> SynValue {
    if label.is_empty() {
        return v;
    }
    match v {
        SynValue::Private(p) => {
            let joined = union(&p.label, &label);
            // Misma etiqueta: reusar el Rc existente (sin alocar).
            if Rc::ptr_eq(&joined, &p.label) || joined.len() == p.label.len() {
                return SynValue::Private(p);
            }
            SynValue::Private(Rc::new(Labelled { value: p.value.clone(), label: joined }))
        }
        SynValue::Secret(_) => v,
        other => SynValue::Private(Rc::new(Labelled { value: other, label })),
    }
}

/// ¿El valor es un contenedor mutable/compuesto (lista, mapa o valor del servidor)? El PC no
/// envuelve contenedores (ver `Interpreter::pc_mark`): sus escalares ya llevan la etiqueta y
/// `label_deep` la ve.
#[inline]
pub fn is_container(v: &SynValue) -> bool {
    matches!(v, SynValue::List(_) | SynValue::Map(_) | SynValue::Server(_))
}

/// Como `mark`, pero **dueña del valor**: si `v` es un contenedor con algún `Rc` COMPARTIDO,
/// lo copia en profundidad antes de envolverlo. Es la que usa el builtin `private(v, p)`.
///
/// Con la versión compartida, `let priv be private(pub, "app")` fabricaba un envoltorio
/// privado sobre el MISMO `Rc` que la variable pública: escribir por el alias es legal (su
/// etiqueta cubre el PC) y mutaba el objeto público, que después se lee sin etiqueta. `mark`
/// (compartida) se queda para el camino de LECTURA —índice/campo/operadores, donde el valor
/// es una referencia que tiene que seguir aliaseada— y para que el host etiquete sus fuentes.
///
/// **Cambio de semántica, documentado** (M5 de la ronda 3): `private(<contenedor>)` devuelve un
/// SNAPSHOT cuando el contenedor tiene otro dueño — mutar el original después no se ve en el
/// privado, y viceversa. Es el precio de cerrar el alias. Cuando NO hay alias vivo (el caso
/// típico: un literal construido en la llamada, `private({…}, "app")`) no se copia nada, así
/// que el envoltorio es gratis: `v` llega por referencia justamente para poder mirar los
/// `Rc::strong_count` sin inflarlos.
pub fn mark_owned(v: &SynValue, label: Label) -> SynValue {
    if label.is_empty() {
        return v.clone();
    }
    if is_container(v) && is_aliased(v) {
        return mark(deep_copy(v), label);
    }
    mark(v.clone(), label)
}

/// ¿Algún contenedor del subárbol tiene más de un dueño? Si no, envolverlo no puede fabricar
/// un alias escribible y la copia de `mark_owned` se saltea (M5: era ~4,5× más lento).
fn is_aliased(v: &SynValue) -> bool {
    match v {
        SynValue::List(l) => Rc::strong_count(l) > 1 || l.borrow().iter().any(is_aliased),
        SynValue::Map(m) => Rc::strong_count(m) > 1 || m.borrow().values().any(is_aliased),
        SynValue::Private(p) => is_aliased(&p.value),
        // Los valores del servidor llevan `Rc`/`Box` opacos: conservador.
        SynValue::Server(_) => true,
        _ => false,
    }
}

/// Copia en profundidad un valor (listas, mapas y valores del servidor se reconstruyen; los
/// escalares y los `Rc` inmutables se comparten). Corta todo aliasing con el original.
pub fn deep_copy(v: &SynValue) -> SynValue {
    match v {
        SynValue::List(l) => syn_list(l.borrow().iter().map(deep_copy).collect()),
        SynValue::Map(m) => {
            let mut out = IndexMap::with_capacity(m.borrow().len());
            for (k, x) in m.borrow().iter() {
                out.insert(k.clone(), deep_copy(x));
            }
            syn_map(out)
        }
        SynValue::Private(p) => {
            SynValue::Private(Rc::new(Labelled { value: deep_copy(&p.value), label: p.label.clone() }))
        }
        SynValue::Server(s) => match &**s {
            ServerValue::Envelope { status, value } => {
                SynValue::Server(Rc::new(ServerValue::Envelope { status: *status, value: deep_copy(value) }))
            }
            ServerValue::Node(m) => {
                let mut out = IndexMap::with_capacity(m.borrow().len());
                for (k, x) in m.borrow().iter() {
                    out.insert(k.clone(), deep_copy(x));
                }
                SynValue::Server(Rc::new(ServerValue::Node(Rc::new(std::cell::RefCell::new(out)))))
            }
            ServerValue::Content(inner) => {
                SynValue::Server(Rc::new(ServerValue::Content(Box::new(deep_copy(inner)))))
            }
            ServerValue::WithHeaders { inner, headers } => SynValue::Server(Rc::new(ServerValue::WithHeaders {
                inner: Box::new(deep_copy(inner)),
                headers: headers.clone(),
            })),
            _ => v.clone(),
        },
        other => other.clone(),
    }
}

/// Ve a través de un `Private` superficial (un nivel).
#[inline]
pub fn unwrap(v: &SynValue) -> &SynValue {
    match v {
        SynValue::Private(p) => &p.value,
        other => other,
    }
}

/// Copia SIN etiquetas (a cualquier profundidad). Para un sumidero que ya comprobó
/// `check_flow` y va a serializar. Los contenedores sin etiquetas dentro se comparten
/// (mismo `Rc`), sólo se reconstruyen los que contienen algo privado.
pub fn strip_deep(v: &SynValue) -> SynValue {
    if !has_label_deep(v) {
        return v.clone();
    }
    match v {
        SynValue::Private(p) => strip_deep(&p.value),
        SynValue::List(l) => syn_list(l.borrow().iter().map(strip_deep).collect()),
        SynValue::Map(m) => {
            let mut out = IndexMap::with_capacity(m.borrow().len());
            for (k, x) in m.borrow().iter() {
                out.insert(k.clone(), strip_deep(x));
            }
            syn_map(out)
        }
        SynValue::Server(s) => match &**s {
            ServerValue::Envelope { status, value } => SynValue::Server(Rc::new(ServerValue::Envelope {
                status: *status,
                value: strip_deep(value),
            })),
            ServerValue::Node(m) => {
                let mut out = IndexMap::with_capacity(m.borrow().len());
                for (k, x) in m.borrow().iter() {
                    out.insert(k.clone(), strip_deep(x));
                }
                SynValue::Server(Rc::new(ServerValue::Node(Rc::new(std::cell::RefCell::new(out)))))
            }
            ServerValue::Content(inner) => {
                SynValue::Server(Rc::new(ServerValue::Content(Box::new(strip_deep(inner)))))
            }
            ServerValue::WithHeaders { inner, headers } => SynValue::Server(Rc::new(ServerValue::WithHeaders {
                inner: Box::new(strip_deep(inner)),
                headers: headers.clone(),
            })),
            // Sin valores anidados: no puede tener etiquetas (has_label_deep ya lo dijo).
            _ => v.clone(),
        },
        other => other.clone(),
    }
}

/// Comprueba que todo lo privado dentro de `v` sea aceptable por un sumidero que acepta a
/// `accepted` (vacío = público): recorre en profundidad y devuelve la PRIMERA violación
/// con su camino (`path` es la raíz, p. ej. `"events"`; los hijos se anotan como
/// `[i]` / `.campo`). La etiqueta efectiva de un valor anidado es la unión de las que lo
/// envuelven.
pub fn check_flow(v: &SynValue, accepted: &[&str], path: &str) -> Result<(), LabelViolation> {
    let acc = label_from(accepted);
    let mut p = String::from(path);
    check_into(v, &acc, &mut p, &empty())
}

fn check_into(v: &SynValue, accepted: &Label, path: &mut String, ctx: &Label) -> Result<(), LabelViolation> {
    match v {
        SynValue::Private(p) => {
            let eff = union(ctx, &p.label);
            if !subset(&eff, accepted) {
                return Err(LabelViolation { path: path.clone(), label: eff, accepted: accepted.clone() });
            }
            check_into(&p.value, accepted, path, &eff)
        }
        SynValue::List(l) => {
            for (i, x) in l.borrow().iter().enumerate() {
                let n = path.len();
                path.push_str(&format!("[{}]", i));
                let r = check_into(x, accepted, path, ctx);
                path.truncate(n);
                r?;
            }
            Ok(())
        }
        SynValue::Map(m) => check_map(&m.borrow(), accepted, path, ctx),
        SynValue::Server(s) => match &**s {
            ServerValue::Envelope { value, .. } => {
                let n = path.len();
                path.push_str(".value");
                let r = check_into(value, accepted, path, ctx);
                path.truncate(n);
                r
            }
            ServerValue::Node(m) => check_map(&m.borrow(), accepted, path, ctx),
            ServerValue::Content(inner) | ServerValue::WithHeaders { inner, .. } => {
                check_into(inner, accepted, path, ctx)
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

fn check_map(
    m: &IndexMap<String, SynValue>,
    accepted: &Label,
    path: &mut String,
    ctx: &Label,
) -> Result<(), LabelViolation> {
    for (k, x) in m.iter() {
        let n = path.len();
        path.push('.');
        path.push_str(k);
        let r = check_into(x, accepted, path, ctx);
        path.truncate(n);
        r?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{syn_int, syn_text};

    fn l(names: &[&str]) -> Label {
        label_from(names)
    }

    #[test]
    fn label_from_normalizes() {
        let x = l(&["b", "a", "b", ""]);
        assert_eq!(label_display_raw(&x), "a,b");
    }

    #[test]
    fn union_and_subset() {
        let a = l(&["a"]);
        let b = l(&["b"]);
        let ab = union(&a, &b);
        assert_eq!(label_display_raw(&ab), "a,b");
        assert!(subset(&a, &ab));
        assert!(!subset(&ab, &a));
        assert!(subset(&empty(), &a));
        assert!(Rc::ptr_eq(&union(&a, &a), &a));
        assert!(Rc::ptr_eq(&union(&empty(), &b), &b));
    }

    #[test]
    fn mark_flattens_and_unions() {
        let v = mark(syn_int(1), l(&["a"]));
        let v = mark(v, l(&["b"]));
        match &v {
            SynValue::Private(p) => {
                assert_eq!(label_display_raw(&p.label), "a,b");
                assert!(matches!(p.value, SynValue::Number(_)));
            }
            _ => panic!("expected Private"),
        }
        assert!(matches!(mark(syn_int(1), empty()), SynValue::Number(_)));
    }

    #[test]
    fn deep_label_and_strip() {
        let inner = mark(syn_int(7), l(&["b"]));
        let list = syn_list(vec![syn_int(1), inner]);
        let outer = mark(list, l(&["a"]));
        assert_eq!(label_display_raw(&label(&outer)), "a");
        assert_eq!(label_display_raw(&label_deep(&outer)), "a,b");
        let stripped = strip_deep(&outer);
        assert!(label_deep(&stripped).is_empty());
        assert_eq!(stripped.to_string(), "[1, 7]");
        // Un contenedor limpio se comparte, no se copia.
        let clean = syn_list(vec![syn_int(1)]);
        match (&clean, &strip_deep(&clean)) {
            (SynValue::List(a), SynValue::List(b)) => assert!(Rc::ptr_eq(a, b)),
            _ => panic!(),
        }
    }

    #[test]
    fn check_flow_paths() {
        let mut data = IndexMap::new();
        data.insert("amount".to_string(), mark(syn_int(5), l(&["app"])));
        let mut ev = IndexMap::new();
        ev.insert("data".to_string(), syn_map(data));
        let events = syn_list(vec![syn_map(ev)]);
        let err = check_flow(&events, &[], "events").unwrap_err();
        assert_eq!(err.path, "events[0].data.amount");
        // T5 (ronda 8): el CAMINO es del valor y sale tal cual (es lo que hay que ir a arreglar);
        // los PRINCIPALES salen del conjunto declarado del programa, constante, porque este
        // `Display` es el que el chequeo de la respuesta HTTP le manda al cliente remoto.
        // Sin programa cargado (un test suelto) no hay conjunto: `…`.
        set_redaction_text("app");
        assert!(
            err.to_string().starts_with(
                "label_violation: events[0].data.amount is private to app, the sink accepts (public); declassify("
            ),
            "{}",
            err
        );
        assert!(check_flow(&events, &["app"], "events").is_ok());
        assert!(check_flow(&events, &["app", "bank"], "events").is_ok());
        // Etiqueta anidada: la efectiva es la unión.
        let nested = mark(syn_list(vec![mark(syn_text("x"), l(&["b"]))]), l(&["a"]));
        let e = check_flow(&nested, &["a"], "r").unwrap_err();
        assert_eq!(e.path, "r[0]");
        assert_eq!(label_display_raw(&e.label), "a,b");
    }
}

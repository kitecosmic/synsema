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
//! Representación: `SynValue::Private(Obj<Labelled>)`, una **variante aislada** del enum
//! (mismo argumento que `secret`, ver `secret.rs`): no es un bit de taint en todos los
//! valores. Con las etiquetas apagadas (`Interpreter::set_labels(false)`, el default) la
//! variante no se construye nunca y el intérprete no ejecuta ningún camino nuevo más allá
//! de un `if self.labels`: coste cero.
//!
//! Invariantes de la variante (los garantiza `mark`):
//!   * nunca `Private` de `Private` (marcar uno existente = unión de etiquetas);
//!   * nunca `Private` con etiqueta vacía (= el valor pelado);
//!   * nunca `Private` de un `Secret` (un secret ya es opaco: `private(secreto, p)` es error, y
//!     un secreto creado, elegido o combinado con algo privado también, con los textos
//!     `SECRET_UNDER_PRIVATE_PC`/`SECRET_FROM_PRIVATE_VALUE` del intérprete; `mark` devuelve el
//!     secret intacto).
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
//!     cruzan: el estático es completo (v0.6.46, E4: `declassify` sólo corre llamado por su
//!     nombre) y el de runtime dice lo que se ejecutó;
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

use crate::types::{MapObj, SynMap};
use std::fmt;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};


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

/// ¿Se creó alguna vez un valor privado en este proceso? Todos nacen en `labelled` (el test
/// `labelled_is_built_only_here` lo fija), así que mientras sea `false` no existe ninguno y
/// recorrer un valor buscándolos no puede encontrar nada. Los valores no cruzan hilos (`Rc`):
/// uno que un hilo ve lo creó ese mismo hilo, después de marcar esto.
static ANY_PRIVATE: AtomicBool = AtomicBool::new(false);

/// El único constructor de `SynValue::Private`.
pub(crate) fn labelled(value: SynValue, label: Label) -> SynValue {
    ANY_PRIVATE.store(true, Ordering::Relaxed);
    SynValue::Private(crate::types::Obj::new(Labelled { value, label }))
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
    /// v0.6.46 (E6.8): se declasificó dentro de una rama decidida por un valor privado. Lo que sale
    /// del proceso (la línea `[INF]`, `receipt()`, el informe del wasm) no cuenta estas entradas:
    /// cuántas hubo decía qué rama se tomó. El registro interno las conserva para el recibo
    /// sellado.
    pub under_private_pc: bool,
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
    /// v0.6.45 (auditoría, ronda 2, M2) — ¿el builtin en curso corre en una rama decidida por un
    /// valor privado (la etiqueta de PC no vacía)? Lo fija el intérprete al despachar un builtin con
    /// las etiquetas encendidas; lo lee el escritor del audit (`stdlib::secrets::write_audit_op`),
    /// que no tiene el intérprete a mano.
    static PC_PRIVATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Fija si el builtin que va a correr está en una rama privada; devuelve lo anterior (para
/// restaurarlo al volver: los builtins se anidan por sus callbacks).
pub fn set_pc_private(v: bool) -> bool {
    PC_PRIVATE.with(|c| c.replace(v))
}

/// Fija el flag mientras vive y restaura el anterior al soltarse (también si el builtin entra en
/// pánico y un worker de `serve` lo atrapa).
/// No es `Send` (el flag es del hilo): no puede soltarse en otro.
pub struct PcPrivateGuard(bool, std::marker::PhantomData<*const ()>);

impl PcPrivateGuard {
    pub fn set(v: bool) -> Self {
        PcPrivateGuard(set_pc_private(v), std::marker::PhantomData)
    }
}

impl Drop for PcPrivateGuard {
    fn drop(&mut self) {
        set_pc_private(self.0);
    }
}

/// ¿El builtin en curso corre en una rama decidida por un valor privado? Siempre `false` con las
/// etiquetas apagadas.
pub fn pc_private_now() -> bool {
    PC_PRIVATE.with(|c| c.get())
}

/// El error de una operación que AUDITA (escribe el log de `reveal`/`sign`/`spend`/`wallet`) dentro
/// de una rama privada: que la entrada exista o no ya dice qué camino tomó la rama, así que no se
/// escribe y la operación no corre. El remedio es decidir con un valor público o desclasificar la
/// condición (queda registrado en `declassify`).
pub fn audited_in_private_branch(op: &str) -> String {
    format!(
        "label_violation: {} writes the audit log, and here it runs in a branch decided by a private value — whether the entry exists would tell which way the branch went; decide with a public value, or declassify(<the condition>, \"<why it may be published>\") it first",
        op
    )
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

/// Fija el texto de redacción de este hilo. Idempotente. El de la corrida lo fija el intérprete en su
/// `RunScope` (v0.6.51, G1): antes un respaldo por PROCESO cubría a los hilos worker del `serve`, y
/// con dos corridas en un proceso la segunda redactaba con los principales de la primera.
pub fn set_redaction_text(text: &str) {
    REDACTION_TEXT.with(|t| {
        let mut t = t.borrow_mut();
        if *t != text {
            t.clear();
            t.push_str(text);
        }
    });
}

/// El texto efectivo: el de este hilo, o el de la corrida para la que trabaja (un worker de `serve`
/// cuyo intérprete se construyó ahí, sin recorrer el programa).
fn redaction_text() -> String {
    let local = REDACTION_TEXT.with(|t| t.borrow().clone());
    if !local.is_empty() {
        return local;
    }
    crate::run_scope::current().map(|r| r.redaction()).unwrap_or_default()
}

/// v0.6.47 (T1) — **el texto fijo de un corte de etiquetas**, el mismo para cualquier sitio y tipo de
/// corte (el del intérprete, el de la respuesta, el de un `stream`, el de un agente): cuál de N sitios
/// cortó lo elige el dato privado. `principals` es el conjunto DECLARADO (`principals_out()`).
pub fn cut_text(principals: &str) -> String {
    format!(
        "label_violation: the flow checker stopped the run (private to {}); what failed, where and how to fix it go to the operator, not to the program",
        principals
    )
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

// The visitor sees a borrowed child BEFORE a continuation retains its owner.
// In particular, testing strong_count must not observe a traversal-made alias.
fn child<R>(v: &SynValue, index: usize, f: impl FnOnce(&SynValue, Option<&str>, Option<usize>) -> R) -> Option<R> {
    match v {
        SynValue::List(l) => {
            let b = l.borrow();
            b.as_values()?.get(index).map(|v| f(v, None, Some(index)))
        }
        SynValue::Map(m) => m.borrow().get_index(index).map(|(k, v)| f(v, Some(k.as_str()), None)),
        SynValue::Private(p) if index == 0 => Some(f(&p.value, None, None)),
        // Tabla (v0.6.65): sólo las columnas `Value` pueden contener un `Private` (los
        // bloques primitivos no tienen dónde colgar una etiqueta); se recorren fila por fila
        // con el camino `.col[row]`, el mismo que arma `check_into`.
        SynValue::Table(t) => {
            let nv = t.value_columns().len();
            if nv == 0 {
                return None;
            }
            let (row, pos) = (index / nv, index % nv);
            let key = format!("{}[{}]", t.value_col_name(pos)?, row);
            t.value_cell_ref(row, pos).map(|v| f(v, Some(&key), None))
        }
        SynValue::Server(s) => match &**s {
            ServerValue::Node(m) => m.borrow().get_index(index).map(|(k, v)| f(v, Some(k.as_str()), None)),
            ServerValue::Envelope { value, .. } if index == 0 => Some(f(value, Some("value"), None)),
            ServerValue::Content(v) | ServerValue::WithHeaders { inner: v, .. } if index == 0 => Some(f(v, None, None)),
            _ => None,
        },
        _ => None,
    }
}

fn walk(v: &SynValue, visit: &mut impl FnMut(&SynValue) -> bool, depth: usize) -> bool {
    if !visit(v) { return false; }
    if depth == 32 { return walk_tail(v, visit); }
    let mut index = 0;
    while let Some(ok) = child(v, index, |v, _, _| walk(v, visit, depth + 1)) {
        if !ok { return false; }
        index += 1;
    }
    true
}

#[cold]
#[inline(never)]
fn walk_tail(v: &SynValue, visit: &mut impl FnMut(&SynValue) -> bool) -> bool {
    let mut stack = vec![(v.clone(), 0)];
    while let Some((v, index)) = stack.last_mut() {
        let next = child(v, *index, |v, _, _| {
            if !visit(v) { return Err(()); }
            // Only retain a child when it has descendants. Numeric lists remain unboxed.
            Ok(child(v, 0, |_, _, _| ()).map(|_| v.clone()))
        });
        *index += 1;
        match next {
            Some(Err(())) => return false,
            Some(Ok(Some(v))) => stack.push((v, 0)),
            Some(Ok(None)) => {},
            None => { stack.pop(); },
        }
    }
    true
}

fn deep_into(v: &SynValue, acc: &mut Label) {
    walk(v, &mut |v| {
        if let SynValue::Private(p) = v { *acc = union(acc, &p.label); }
        true
    }, 0);
}

/// ¿Hay alguna etiqueta en el valor (a cualquier profundidad)?
pub fn has_label_deep(v: &SynValue) -> bool {
    !walk(v, &mut |v| !matches!(v, SynValue::Private(p) if !p.label.is_empty()), 0)
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
            labelled(p.value.clone(), joined)
        }
        SynValue::Secret(_) => v,
        other => labelled(other, label),
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
    !walk(v, &mut |v| match v {
        SynValue::List(l) => crate::types::ListRef::strong_count(l) <= 1,
        SynValue::Map(m) => crate::types::MapRef::strong_count(m) <= 1,
        SynValue::Server(_) => false,
        _ => true,
    }, 0)
}

/// Copia en profundidad un valor (listas, mapas y valores del servidor se reconstruyen; los
/// escalares y los `Rc` inmutables se comparten). Corta todo aliasing con el original.
pub fn deep_copy(v: &SynValue) -> SynValue {
    copy_walk(v, false, 0).0
}

// Rebuild only a changed branch when stripping. Clean siblings are shared, and
// no subtree is scanned again to decide whether its parent needs rebuilding.
fn rebuild(v: &SynValue, mut values: Vec<SynValue>, strip: bool) -> SynValue {
    match v {
        SynValue::List(_) => syn_list(values),
        SynValue::Map(m) => {
            let m = m.borrow();
            let mut out = SynMap::with_capacity(m.len());
            for (index, value) in values.into_iter().enumerate() {
                out.insert(m.get_index(index).unwrap().0.clone(), value);
            }
            syn_map(out)
        }
        SynValue::Private(p) => {
            let value = values.pop().unwrap();
            if strip { value } else { labelled(value, p.label.clone()) }
        }
        SynValue::Server(s) => {
            let out = match &**s {
                ServerValue::Envelope { status, .. } => ServerValue::Envelope { status: *status, value: values.pop().unwrap() },
                ServerValue::Node(m) => {
                    let m = m.borrow();
                    let mut out = SynMap::with_capacity(m.len());
                    for (index, value) in values.into_iter().enumerate() {
                        out.insert(m.get_index(index).unwrap().0.clone(), value);
                    }
                    ServerValue::Node(out.into_ref())
                }
                ServerValue::Content(_) => ServerValue::Content(Box::new(values.pop().unwrap())),
                ServerValue::WithHeaders { headers, .. } => ServerValue::WithHeaders { inner: Box::new(values.pop().unwrap()), headers: headers.clone() },
                _ => return v.clone(),
            };
            SynValue::Server(crate::types::Obj::new(out))
        }
        // Tabla (v0.6.65): las columnas `Value` reconstruidas salen en un `Obj` nuevo; las
        // primitivas se comparten (columns.rs `rebuild_values`).
        SynValue::Table(t) => SynValue::Table(crate::types::Obj::new(t.rebuild_values(values))),
        _ => v.clone(),
    }
}

fn copy_leaf(v: &SynValue, strip: bool) -> Option<(SynValue, bool)> {
    if let SynValue::List(l) = v {
        let b = l.borrow();
        if b.as_values().is_none() {
            return Some((if strip { v.clone() } else { crate::types::syn_list_of(b.clone()) }, false));
        }
    }
    if matches!(v, SynValue::List(_) | SynValue::Map(_) | SynValue::Private(_) | SynValue::Table(_)) {
        return None;
    }
    if let SynValue::Server(s) = v {
        if matches!(&**s, ServerValue::Envelope { .. } | ServerValue::Node(_) | ServerValue::Content(_) | ServerValue::WithHeaders { .. }) {
            return None;
        }
    }
    Some((v.clone(), false))
}

fn append_copy(v: &SynValue, index: usize, out: &mut Option<Vec<SynValue>>, value: SynValue, changed: bool) {
    if changed && out.is_none() {
        let mut prefix = Vec::new();
        for i in 0..index { prefix.push(child(v, i, |v, _, _| v.clone()).unwrap()); }
        *out = Some(prefix);
    }
    if let Some(out) = out { out.push(value); }
}

fn copy_walk(v: &SynValue, strip: bool, depth: usize) -> (SynValue, bool) {
    if let Some(value) = copy_leaf(v, strip) { return value; }
    if depth == 32 { return copy_tail(v, strip); }
    let mut out = if strip { None } else { Some(Vec::new()) };
    let mut index = 0;
    let mut changed = strip && matches!(v, SynValue::Private(_));
    while let Some((value, dirty)) = child(v, index, |v, _, _| copy_walk(v, strip, depth + 1)) {
        append_copy(v, index, &mut out, value, dirty || changed);
        changed |= dirty;
        index += 1;
    }
    (out.map_or_else(|| v.clone(), |out| rebuild(v, out, strip)), changed)
}

struct CopyFrame {
    value: SynValue,
    index: usize,
    out: Option<Vec<SynValue>>,
    changed: bool,
}

impl CopyFrame {
    fn new(v: &SynValue, strip: bool) -> Self {
        Self { value: v.clone(), index: 0, out: if strip { None } else { Some(Vec::new()) }, changed: strip && matches!(v, SynValue::Private(_)) }
    }
}

#[cold]
#[inline(never)]
fn copy_tail(v: &SynValue, strip: bool) -> (SynValue, bool) {
    let mut stack = vec![CopyFrame::new(v, strip)];
    loop {
        let frame = stack.last_mut().unwrap();
        match child(&frame.value, frame.index, |v, _, _| {
            copy_leaf(v, strip).map_or_else(|| Err(CopyFrame::new(v, strip)), Ok)
        }) {
            Some(Err(next)) => { stack.push(next); continue; }
            Some(Ok((value, dirty))) => {
                append_copy(&frame.value, frame.index, &mut frame.out, value, dirty || frame.changed);
                frame.changed |= dirty;
                frame.index += 1;
            }
            None => {
                let frame = stack.pop().unwrap();
                let value = frame.out.map_or_else(|| frame.value.clone(), |out| rebuild(&frame.value, out, strip));
                let Some(parent) = stack.last_mut() else { return (value, frame.changed); };
                append_copy(&parent.value, parent.index, &mut parent.out, value, frame.changed || parent.changed);
                parent.changed |= frame.changed;
                parent.index += 1;
            }
        }
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
    if !ANY_PRIVATE.load(Ordering::Relaxed) { return v.clone(); }
    copy_walk(v, true, 0).0
}

/// Comprueba que todo lo privado dentro de `v` sea aceptable por un sumidero que acepta a
/// `accepted` (vacío = público): recorre en profundidad y devuelve la PRIMERA violación
/// con su camino (`path` es la raíz, p. ej. `"events"`; los hijos se anotan como
/// `[i]` / `.campo`). La etiqueta efectiva de un valor anidado es la unión de las que lo
/// envuelven.
pub fn check_flow(v: &SynValue, accepted: &[&str], path: &str) -> Result<(), LabelViolation> {
    // Lo común es que no haya nada privado: sin ningún valor privado en el proceso, o sin
    // ninguno dentro de `v`, no hay violación posible. Así una respuesta que da una página de
    // una colección grande no la recorre entera armando caminos en cada request; el recorrido
    // con caminos corre sólo si hay algo que reportar.
    if !ANY_PRIVATE.load(Ordering::Relaxed) || !holds_private(v) {
        return Ok(());
    }
    let acc = label_from(accepted);
    let mut p = String::from(path);
    check_into(v, &acc, &mut p, &empty(), 0)
}

fn check_into(v: &SynValue, accepted: &Label, path: &mut String, ctx: &Label, depth: usize) -> Result<(), LabelViolation> {
    if depth == 32 { return check_tail(v, accepted, path, ctx); }
    match v {
        SynValue::Private(p) => {
            let eff = union(ctx, &p.label);
            if !subset(&eff, accepted) {
                return Err(LabelViolation { path: path.clone(), label: eff, accepted: accepted.clone() });
            }
            check_into(&p.value, accepted, path, &eff, depth + 1)
        }
        SynValue::List(l) => {
            // Una lista sin caja (enteros/floats) no tiene nada privado; leerla con
            // `list_values` la pasaba a valores para siempre.
            let b = l.borrow();
            let Some(xs) = b.as_values() else { return Ok(()) };
            for (i, x) in xs.iter().enumerate() {
                let n = path.len();
                path.push_str(&format!("[{}]", i));
                let r = check_into(x, accepted, path, ctx, depth + 1);
                path.truncate(n);
                r?;
            }
            Ok(())
        }
        SynValue::Map(m) => check_map(&m.borrow(), accepted, path, ctx, depth),
        // Tabla (v0.6.65): recorre las columnas `Value` (las primitivas no pueden llevar un
        // `Private`) con el camino `.col[row]`.
        SynValue::Table(t) => {
            let mut r = Ok(());
            t.for_each_value_cell(|row, col, x| {
                let n = path.len();
                path.push('.');
                path.push_str(col);
                path.push_str(&format!("[{}]", row));
                let rr = check_into(x, accepted, path, ctx, depth + 1);
                path.truncate(n);
                let ok = rr.is_ok();
                if r.is_ok() {
                    r = rr;
                }
                ok
            });
            r
        }
        SynValue::Server(s) => match &**s {
            ServerValue::Envelope { value, .. } => {
                let n = path.len();
                path.push_str(".value");
                let r = check_into(value, accepted, path, ctx, depth + 1);
                path.truncate(n);
                r
            }
            ServerValue::Node(m) => check_map(&m.borrow(), accepted, path, ctx, depth),
            ServerValue::Content(inner) | ServerValue::WithHeaders { inner, .. } => {
                check_into(inner, accepted, path, ctx, depth + 1)
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

#[cold]
#[inline(never)]
fn check_tail(v: &SynValue, accepted: &Label, path: &mut String, ctx: &Label) -> Result<(), LabelViolation> {
    fn effective(v: &SynValue, accepted: &Label, path: &str, ctx: &Label) -> Result<Label, LabelViolation> {
        if let SynValue::Private(p) = v {
            let eff = union(ctx, &p.label);
            if !subset(&eff, accepted) {
                return Err(LabelViolation { path: path.to_owned(), label: eff, accepted: accepted.clone() });
            }
            Ok(eff)
        } else { Ok(ctx.clone()) }
    }
    let base = path.len();
    let ctx = effective(v, accepted, path, ctx)?;
    let mut stack = vec![(v.clone(), 0, base, ctx)];
    while let Some((v, index, length, ctx)) = stack.last_mut() {
        path.truncate(*length);
        let next = child(v, *index, |v, key, index| {
            use std::fmt::Write;
            if let Some(index) = index { write!(path, "[{}]", index).unwrap(); }
            else if let Some(key) = key {
                path.push('.'); path.push_str(key);
            }
            let ctx = effective(v, accepted, path, ctx)?;
            Ok((v.clone(), 0, path.len(), ctx))
        });
        *index += 1;
        match next {
            Some(Ok(next)) => stack.push(next),
            Some(Err(e)) => { path.truncate(base); return Err(e); }
            None => { stack.pop(); },
        }
    }
    path.truncate(base);
    Ok(())
}

/// ¿Hay algún valor privado en lo que `check_into` recorre? Sin caminos ni reservas.
fn holds_private(v: &SynValue) -> bool {
    !walk(v, &mut |v| !matches!(v, SynValue::Private(_)), 0)
}

fn check_map(
    m: &MapObj,
    accepted: &Label,
    path: &mut String,
    ctx: &Label,
    depth: usize,
) -> Result<(), LabelViolation> {
    for (k, x) in m.iter() {
        let n = path.len();
        path.push('.');
        path.push_str(k);
        let r = check_into(x, accepted, path, ctx, depth + 1);
        path.truncate(n);
        r?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{syn_int, syn_text};

    /// v0.6.51 (G1-5): un hilo sin texto propio (un worker de `serve` cuyo intérprete no recorrió el
    /// programa) redacta con el de SU corrida — no con el del primer programa del proceso.
    #[test]
    fn g1_5_a_thread_without_its_own_text_redacts_with_its_run() {
        use crate::run_scope::RunScope;
        let (a, b) = (RunScope::new(), RunScope::new());
        a.set_redaction("app");
        b.set_redaction("bank");
        std::thread::spawn(move || {
            assert_eq!(redaction_text(), "");
            {
                let _e = a.enter();
                assert_eq!(redaction_text(), "app");
            }
            {
                let _e = b.enter();
                assert_eq!(redaction_text(), "bank");
            }
            // El del hilo sigue mandando.
            set_redaction_text("local");
            let _e = a.enter();
            assert_eq!(redaction_text(), "local");
        })
        .join()
        .unwrap();
    }

    /// v0.6.51 (G1-5): el intérprete que recorrió el programa le deja a su corrida el conjunto
    /// declarado, que es lo que leen los demás hilos de esa corrida.
    #[test]
    fn g1_5_the_interpreter_gives_its_run_the_declared_set() {
        let p = crate::parser::parse_source("let x be private(1, \"app\")\n", "g1.syn").unwrap();
        let mut i = crate::interpreter::Interpreter::new();
        let _ = i.execute(&p);
        assert_eq!(i.run_scope().redaction(), "app");
        let other = crate::interpreter::Interpreter::new();
        assert_eq!(other.run_scope().redaction(), "", "otra corrida no lo ve");
    }

    fn nested(mut v: SynValue, depth: usize, maps: bool) -> SynValue {
        for _ in 0..depth {
            v = if maps {
                let mut m = SynMap::new(); m.insert("", v); syn_map(m)
            } else { syn_list(vec![v]) };
        }
        v
    }

    #[test]
    fn deep_copy_labels_strip_and_paths() {
        for maps in [false, true] {
            for depth in [0, 31, 32, 33, 1000, 50000] {
                let v = nested(mark(syn_int(7), l(&["b"])), depth, maps);
                assert_eq!(label_display_raw(&label_deep(&v)), "b");
                assert!(has_label_deep(&v));
                let copied = deep_copy(&v);
                assert!(!is_aliased(&copied), "copy must sever every mutable alias");
                assert!(copied.syn_equals(&v));
                assert_eq!(label_display_raw(&label_deep(&copied)), "b");
                let clean = strip_deep(&v);
                assert!(!has_label_deep(&clean));
                assert!(!holds_private(&clean));
                assert!(clean.syn_equals(&v));
                let e = check_flow(&v, &[], "root").unwrap_err();
                assert_eq!(e.path, format!("root{}", if maps { "." } else { "[0]" }.repeat(depth)));
                assert!(check_flow(&v, &["b"], "root").is_ok());
                let wrapped = mark(v, l(&["a"]));
                let e = check_flow(&wrapped, &["a"], "root").unwrap_err();
                assert_eq!(label_display_raw(&e.label), "a,b");
            }
        }
    }

    #[test]
    fn deep_alias_observation_and_clean_branch_identity() {
        let v = nested(syn_int(7), 50000, false);
        assert!(!is_aliased(&v), "the traversal must not fabricate an alias");
        let leaf = syn_list(vec![syn_int(9)]);
        let v = nested(leaf.clone(), 50000, true);
        assert!(is_aliased(&v), "a deep genuine alias must be found");
        let private = mark_owned(&v, l(&["owner"]));
        assert!(private.syn_equals(&v));
        let clean = syn_list(vec![syn_int(2)]);
        let tree = syn_list(vec![clean.clone(), nested(mark(syn_int(1), l(&["x"])), 1000, false)]);
        let stripped = strip_deep(&tree);
        let SynValue::List(xs) = stripped else { panic!() };
        let b = xs.borrow();
        let SynValue::List(branch) = &b.as_values().unwrap()[0] else { panic!() };
        let SynValue::List(original) = &clean else { panic!() };
        assert!(crate::types::ListRef::ptr_eq(original, branch));
        let numeric = crate::types::syn_list_of(crate::synlist::SynList::from_ints(vec![1, 2]));
        let _ = label_deep(&numeric);
        let _ = strip_deep(&numeric);
        let copy = deep_copy(&numeric);
        for v in [&numeric, &copy] {
            let SynValue::List(l) = v else { panic!() };
            assert!(l.borrow().as_values().is_none());
        }
        let (SynValue::List(a), SynValue::List(b)) = (&numeric, &copy) else { panic!() };
        assert!(!crate::types::ListRef::ptr_eq(a, b));
    }

    #[test]
    fn deep_server_copy_strip_and_first_violation() {
        use crate::types::Obj;
        let mut v = mark(syn_int(7), l(&["deep"]));
        for i in 0..50000 {
            v = SynValue::Server(Obj::new(match i % 4 {
                0 => { ServerValue::Envelope { status: 201, value: v } },
                1 => { let mut m = SynMap::new(); m.insert("", v); ServerValue::Node(m.into_ref()) },
                2 => ServerValue::Content(Box::new(v)),
                _ => ServerValue::WithHeaders { inner: Box::new(v), headers: vec![("x".into(), "y".into())] },
            }));
        }
        let copy = deep_copy(&v);
        assert!(copy.syn_equals(&v));
        let clean = strip_deep(&v);
        assert!(!has_label_deep(&clean));
        // The wrappers were built from the leaf outward; reverse the path segments.
        let e = check_flow(&v, &[], "r").unwrap_err();
        assert_eq!(e.path, format!("r{}", "..value".repeat(12500)));
        assert!(check_flow(&v, &["deep"], "r").is_ok());
        let mut map = SynMap::new();
        map.insert("first", mark(syn_int(1), l(&["first"])));
        map.insert("second", v);
        let e = check_flow(&syn_map(map), &[], "r").unwrap_err();
        assert_eq!(e.path, "r.first");
        assert_eq!(label_display_raw(&e.label), "first");
    }

    #[test]
    fn labels_million_with_normal_drop() {
        std::thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(|| {
            let v = nested(mark(syn_int(7), l(&["owner"])), 1_000_000, false);
            assert!(has_label_deep(&v));
            assert_eq!(label_display_raw(&label_deep(&v)), "owner");
            let copy = deep_copy(&v);
            assert!(copy.syn_equals(&v));
            drop(copy);
            let clean = strip_deep(&v);
            assert!(!has_label_deep(&clean));
            drop(clean);
            assert!(check_flow(&v, &["owner"], "r").is_ok());
            let e = check_flow(&v, &[], "r").unwrap_err();
            assert_eq!(e.path.len(), 3_000_001);
        }).unwrap().join().unwrap();
    }

    fn l(names: &[&str]) -> Label {
        label_from(names)
    }

    /// `check_flow` se saltea el recorrido mientras no se haya creado ningún valor privado: eso
    /// sólo es cierto si todos nacen en `labelled`. Un `Labelled { … }` armado en otro lado (en
    /// cualquier crate del motor o en los guests) se lo saltearía en silencio.
    #[test]
    fn labelled_is_built_only_here() {
        fn walk(dir: &std::path::Path, found: &mut Vec<String>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if p.is_dir() {
                    if name != "target" && !name.starts_with('.') {
                        walk(&p, found);
                    }
                } else if name.ends_with(".rs") {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    // Armado acá para que este test no se encuentre a sí mismo.
                    let pat = ["Labelled", " {"].concat();
                    for (i, line) in text.lines().enumerate() {
                        let t = line.trim();
                        if t.contains(&pat) && !t.starts_with("//") {
                            found.push(format!("{}:{}: {}", p.display(), i + 1, t));
                        }
                    }
                }
            }
        }
        let pat = ["Labelled", " {"].concat();
        let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = Vec::new();
        walk(&core.join(".."), &mut found);
        walk(&core.join("../../../packages"), &mut found);
        let allowed = [
            [": pub struct ", &pat[..8], " {"].concat(),
            [": SynValue::Private(crate::types::Obj::new(", &pat, " value, label }))"].concat(),
        ];
        let bad: Vec<_> = found.iter().filter(|f| !allowed.iter().any(|a| f.ends_with(a))).collect();
        assert!(bad.is_empty(), "valores privados construidos fuera de `labels::labelled`: {:#?}", bad);
        assert_eq!(found.len(), 2, "{:#?}", found);
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
            (SynValue::List(a), SynValue::List(b)) => assert!(crate::types::ListRef::ptr_eq(a, b)),
            _ => panic!(),
        }
    }

    #[test]
    fn check_flow_paths() {
        let mut data = SynMap::new();
        data.insert("amount", mark(syn_int(5), l(&["app"])));
        let mut ev = SynMap::new();
        ev.insert("data", syn_map(data));
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

    /// v0.6.65: una tabla recorre igual que una lista de mapas — sólo las columnas `Value`
    /// pueden contener un `Private` (los bloques primitivos no tienen dónde), y el camino
    /// nombra la columna y la fila. `deep_copy` corta el aliasing conservando la etiqueta.
    #[test]
    fn a_table_cell_is_a_label_path() {
        use crate::columns;
        let mut r0 = SynMap::new();
        r0.insert("k", syn_int(1));
        r0.insert("v", mark(syn_int(5), l(&["app"])));
        let mut r1 = SynMap::new();
        r1.insert("k", syn_int(2));
        r1.insert("v", syn_int(7));
        let rows = vec![syn_map(r0), syn_map(r1)];
        let table = SynValue::Table(crate::types::Obj::new(
            columns::build_from_rows(&rows).expect("tabla de prueba"),
        ));
        // La celda privada hace la columna `Value`; el recorrido la ve.
        assert_eq!(label_display_raw(&label_deep(&table)), "app");
        assert!(has_label_deep(&table));
        // El sumidero la encuentra con el camino `.v[0]`, y pasa si lo acepta.
        let err = check_flow(&table, &[], "t").unwrap_err();
        assert_eq!(err.path, "t.v[0]");
        assert!(check_flow(&table, &["app"], "t").is_ok());
        // deep_copy corta el aliasing y conserva la etiqueta.
        let copy = deep_copy(&table);
        assert_eq!(label_display_raw(&label_deep(&copy)), "app");
        assert!(copy.syn_equals(&table));
    }
}

//! Modelo de valores de Synsema.
//!
//! Port de `synsema/core/types.py`. En Python todo valor es un `SynValue` que
//! envuelve el raw + tipo + origin + capabilities + metadata. Acá `SynValue` es
//! un enum por variante de valor. list/map son **tipos de referencia mutables**
//! (`Rc<RefCell<…>>`) para replicar el aliasing de Python; los maps son ordenados
//! (`IndexMap`) porque el dict de Python preserva el orden de inserción.
//!
//! NOTA de paridad (origin/igualdad): el `SynValue.__eq__` de Python (dataclass)
//! compara también `type` (instancias distintas) y `origin`, lo que vuelve la
//! igualdad de listas/maps sensible al origen. Acá `==` se implementa por **valor**
//! (lo intuitivo). Si el corpus exige el quirk del origen, se ajusta — pendiente de
//! confirmar con el agente de testing.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use indexmap::IndexMap;
use ndarray::ArrayD;
use num_complex::Complex64;

use crate::ast::{Node, Param};
use crate::interpreter::{BuiltinTask, Environment};
use crate::number::{py_float_str, Number};
use crate::secret::{constant_time_eq, SecretInner};
use crate::tokens::SourceLocation;

pub type ListRef = Rc<RefCell<Vec<SynValue>>>;
pub type MapRef = Rc<RefCell<IndexMap<String, SynValue>>>;

#[derive(Clone)]
pub enum SynValue {
    Number(Number),
    Text(Rc<str>),
    Bool(bool),
    Nothing,
    List(ListRef),
    Map(MapRef),
    Task(Rc<SynTaskValue>),
    Builtin(Rc<BuiltinTask>),
    /// Valor del servidor HTTP con `metadata` (espeja el `metadata` del SynValue
    /// Python: `_RAW`/`_ENVELOPE`/`_NODE`/`_CONTENT`/`_PAGED`). En el lenguaje se
    /// comporta como un map (type "map", property access, etc.); el tag sólo lo
    /// lee la lógica de `serve` (contrato de respuesta + negociación).
    Server(Rc<ServerValue>),
    /// Valor sensible y opaco (feature `secret`). Variante **aislada** (§8): no es
    /// un bit de taint en los otros valores — es un tag más del enum. Se redacta en
    /// toda salida (Display/JSON/blackboard/logs); el plaintext sólo se materializa
    /// en los puntos bordeados del runtime (reveal/socket/DB). Ver `secret.rs`.
    Secret(Rc<SecretInner>),
    /// Datos binarios inmutables (feature `bytes`, Batch 1). Espeja `Text(Rc<str>)`
    /// pero sin garantía de UTF-8. Constructor-only (`bytes(...)`); no hay literal.
    /// Toda operación devuelve bytes nuevos (sin mutación in-place → sin aliasing).
    Bytes(Rc<[u8]>),
    /// Número complejo (feature math, Batch 4). Variante **aislada** (como `bytes`): NO
    /// vive en el tower `Number` (Int/Big/Float/Decimal queda intacto, G1/G2). La
    /// aritmética se resuelve en `exec_binary` (promoción real→complex). Constructor-only
    /// `complex(re, im)` (sin literal `2i`). Basado en float (`Complex64`).
    Complex(Complex64),
    /// Array numérico n-dimensional (feature math, Batch 5). Variante **aislada** (como
    /// `bytes`/`complex`): NO vive en el tower `Number`. dtype `f64`, inmutable (las ops
    /// devuelven arrays nuevos). La aritmética vectorizada (elementwise + broadcasting) se
    /// resuelve en `exec_binary`; el álgebra lineal (faer) opera sobre el caso 2D.
    /// `*` es ELEMENTWISE (Hadamard); el producto matricial es `matmul`/`dot`.
    Array(Rc<ArrayD<f64>>),
}

/// Closure de paginación lazy de `paged()`: `fetch(limit, offset) → (filas, total)`.
/// `limit = None` materializa todo. Devuelve Err con mensaje si la query falla.
pub type PagedFetch = dyn Fn(Option<i64>, i64) -> Result<(Vec<SynValue>, i64), String>;

/// Variantes de valor del servidor (cada una lleva un tag implícito por su variante).
pub enum ServerValue {
    /// `html()`/`respond()`/`render()` — body escrito verbatim. (_RAW)
    Raw { body: String, content_type: String, status: i64 },
    /// `binary()` / `give bytes(...)` — body binario crudo escrito verbatim al socket
    /// (sin negociación de contenido). Espeja `Raw` pero con body `Vec<u8>`. (Batch 1)
    RawBytes { body: Vec<u8>, content_type: String, status: i64 },
    /// `ok()`/`created()`/`not_found()`/`fail()` — status + valor interno. (_ENVELOPE)
    Envelope { status: i64, value: SynValue },
    /// Nodo de contenido (`heading`/`prose`/`list`/…): map `{kind, …}`. (_NODE)
    Node(MapRef),
    /// `content()` — árbol negociable (HTML/MD/JSON). Envuelve un nodo. (_CONTENT)
    Content(Box<SynValue>),
    /// `redirect()` — respuesta 3xx con header `Location` y sin body. (_REDIRECT)
    Redirect { location: String, status: i64 },
    /// `paged()` — paginación lazy vía SQL. (_PAGED)
    Paged(Rc<PagedFetch>),
}

impl ServerValue {
    /// Acceso a campo (`<campo> of x`) — espeja `x.raw[campo]` del map subyacente.
    pub fn get_field(&self, key: &str) -> Option<SynValue> {
        match self {
            ServerValue::Raw { body, content_type, status } => match key {
                "body" => Some(syn_text(body.as_str())),
                "content_type" => Some(syn_text(content_type.as_str())),
                "status" => Some(syn_int(*status)),
                _ => None,
            },
            ServerValue::RawBytes { body, content_type, status } => match key {
                "body" => Some(syn_bytes(body.clone())),
                "content_type" => Some(syn_text(content_type.as_str())),
                "status" => Some(syn_int(*status)),
                _ => None,
            },
            ServerValue::Envelope { status, value } => match key {
                "status" => Some(syn_int(*status)),
                "value" => Some(value.clone()),
                _ => None,
            },
            ServerValue::Node(m) => m.borrow().get(key).cloned(),
            ServerValue::Redirect { location, status } => match key {
                "location" => Some(syn_text(location.as_str())),
                "status" => Some(syn_int(*status)),
                _ => None,
            },
            ServerValue::Content(_) | ServerValue::Paged(_) => None,
        }
    }
}

/// Un task definido por el usuario, con su entorno de cierre (closure).
pub struct SynTaskValue {
    pub name: String,
    /// Parámetros (nombre + default opcional). El default se evalúa en call time (G5).
    pub parameters: Vec<Param>,
    pub body: Vec<Node>,
    pub closure_env: Rc<RefCell<Environment>>,
    pub origin: Option<SourceLocation>,
    /// (capability, scope) declaradas con `require` dentro del task.
    pub required_capabilities: Vec<(String, Option<String>)>,
}

impl SynValue {
    /// Nombre del tipo (para `type_of` y mensajes de error). Espeja `type.name`.
    pub fn type_name(&self) -> &'static str {
        match self {
            // `decimal` es un tipo de primera clase (vive dentro de Number, junto a
            // Int/Float/Big). Abrir el sub-enum para que reporte su propio nombre, como
            // complex/bytes/array (DE-021).
            SynValue::Number(n) => if n.is_decimal() { "decimal" } else { "number" },
            SynValue::Text(_) => "text",
            SynValue::Bool(_) => "bool",
            SynValue::Nothing => "nothing",
            SynValue::List(_) => "list",
            SynValue::Map(_) => "map",
            SynValue::Task(_) | SynValue::Builtin(_) => "task",
            // type=SynMap() en el oráculo para todos los valores del servidor.
            SynValue::Server(_) => "map",
            SynValue::Secret(_) => "secret",
            SynValue::Bytes(_) => "bytes",
            SynValue::Complex(_) => "complex",
            SynValue::Array(_) => "array",
        }
    }

    /// ¿Es un valor `secret` (tainted/opaco)? Comprobación de discriminante O(1).
    #[inline]
    pub fn is_secret(&self) -> bool {
        matches!(self, SynValue::Secret(_))
    }

    /// Veracidad: nothing/false/0/""/[]/{} → false; el resto → true.
    pub fn is_truthy(&self) -> bool {
        match self {
            SynValue::Nothing => false,
            SynValue::Bool(b) => *b,
            SynValue::Number(n) => !n.is_zero(),
            SynValue::Text(s) => !s.is_empty(),
            SynValue::List(l) => !l.borrow().is_empty(),
            SynValue::Map(m) => !m.borrow().is_empty(),
            SynValue::Task(_) | SynValue::Builtin(_) => true,
            SynValue::Server(_) => true,
            // Un secret con plaintext no vacío es truthy (chequeo de longitud, no
            // expone el valor).
            SynValue::Secret(s) => !s.expose_bytes().is_empty(),
            // Bytes vacío = false (como text/list vacíos).
            SynValue::Bytes(b) => !b.is_empty(),
            // complex(0,0) = false; cualquier parte no-cero = true.
            SynValue::Complex(z) => z.re != 0.0 || z.im != 0.0,
            // Array no-vacío = true (espeja list).
            SynValue::Array(a) => !a.is_empty(),
        }
    }

    /// Igualdad por valor (operador `==`/`!=`, `match`, `contains`).
    pub fn syn_equals(&self, other: &SynValue) -> bool {
        match (self, other) {
            // Secret: igualdad en **tiempo constante** (no filtra por timing, §5).
            // Comparar dos plaintexts internamente no los expone a user-space.
            (SynValue::Secret(a), SynValue::Secret(b)) => {
                constant_time_eq(a.expose_bytes(), b.expose_bytes())
            }
            (SynValue::Secret(a), SynValue::Text(b)) | (SynValue::Text(b), SynValue::Secret(a)) => {
                constant_time_eq(a.expose_bytes(), b.as_bytes())
            }
            (SynValue::Number(a), SynValue::Number(b)) => a.num_eq(b),
            (SynValue::Bool(a), SynValue::Bool(b)) => a == b,
            // Python: True == 1 (bool es subclase de int).
            (SynValue::Number(a), SynValue::Bool(b)) | (SynValue::Bool(b), SynValue::Number(a)) => {
                a.num_eq(&Number::Int(if *b { 1 } else { 0 }))
            }
            (SynValue::Text(a), SynValue::Text(b)) => a == b,
            (SynValue::Nothing, SynValue::Nothing) => true,
            (SynValue::List(a), SynValue::List(b)) => {
                let (a, b) = (a.borrow(), b.borrow());
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.syn_equals(y))
            }
            (SynValue::Map(a), SynValue::Map(b)) => {
                let (a, b) = (a.borrow(), b.borrow());
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.get(k).map_or(false, |w| v.syn_equals(w)))
            }
            // Igualdad de valores del servidor (estructural). Un Server NUNCA es
            // igual a un map plano (en el oráculo difieren en metadata).
            (SynValue::Server(a), SynValue::Server(b)) => match (&**a, &**b) {
                (
                    ServerValue::Raw { body: b1, content_type: c1, status: s1 },
                    ServerValue::Raw { body: b2, content_type: c2, status: s2 },
                ) => b1 == b2 && c1 == c2 && s1 == s2,
                (
                    ServerValue::RawBytes { body: b1, content_type: c1, status: s1 },
                    ServerValue::RawBytes { body: b2, content_type: c2, status: s2 },
                ) => b1 == b2 && c1 == c2 && s1 == s2,
                (
                    ServerValue::Envelope { status: s1, value: v1 },
                    ServerValue::Envelope { status: s2, value: v2 },
                ) => s1 == s2 && v1.syn_equals(v2),
                (ServerValue::Node(m1), ServerValue::Node(m2)) => {
                    let (m1, m2) = (m1.borrow(), m2.borrow());
                    m1.len() == m2.len()
                        && m1.iter().all(|(k, v)| m2.get(k).map_or(false, |w| v.syn_equals(w)))
                }
                (ServerValue::Content(a), ServerValue::Content(b)) => a.syn_equals(b),
                (ServerValue::Paged(a), ServerValue::Paged(b)) => Rc::ptr_eq(a, b),
                (
                    ServerValue::Redirect { location: l1, status: s1 },
                    ServerValue::Redirect { location: l2, status: s2 },
                ) => l1 == l2 && s1 == s2,
                _ => false,
            },
            // `bytes` sólo es igual a `bytes` (byte-a-byte). Nunca igual a text ni a
            // ningún otro tipo (cae al `_ => false`): no hay igualdad cross-type (G3).
            (SynValue::Bytes(a), SynValue::Bytes(b)) => a == b,
            // Complex (Batch 4, G4): igualdad por valor; y Pythónico `complex(a,0) == a`
            // (un complejo con parte imaginaria 0 iguala al real correspondiente).
            (SynValue::Complex(a), SynValue::Complex(b)) => a == b,
            (SynValue::Complex(z), SynValue::Number(n))
            | (SynValue::Number(n), SynValue::Complex(z)) => z.im == 0.0 && z.re == n.to_f64(),
            // Array (Batch 5): misma shape Y mismos datos. Nunca igual a otro tipo.
            (SynValue::Array(a), SynValue::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl fmt::Display for SynValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SynValue::Nothing => write!(f, "nothing"),
            SynValue::Bool(b) => write!(f, "{}", if *b { "true" } else { "false" }),
            SynValue::Number(n) => write!(f, "{}", n),
            SynValue::Text(s) => write!(f, "{}", s),
            SynValue::List(l) => {
                let parts: Vec<String> = l.borrow().iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", parts.join(", "))
            }
            SynValue::Map(m) => {
                let parts: Vec<String> = m
                    .borrow()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                write!(f, "{{{}}}", parts.join(", "))
            }
            SynValue::Task(t) => {
                let names: Vec<&str> = t.parameters.iter().map(|p| p.name.as_str()).collect();
                write!(f, "task {}({})", t.name, names.join(", "))
            }
            SynValue::Builtin(b) => write!(f, "builtin:{}", b.name),
            // str() de un valor del servidor: repr map-like de su dict subyacente.
            SynValue::Server(s) => match &**s {
                ServerValue::Raw { body, content_type, status } => write!(
                    f,
                    "{{body: {}, content_type: {}, status: {}}}",
                    body, content_type, status
                ),
                ServerValue::RawBytes { body, content_type, status } => write!(
                    f,
                    "{{body: {}, content_type: {}, status: {}}}",
                    bytes_display(body), content_type, status
                ),
                ServerValue::Envelope { status, value } => {
                    write!(f, "{{status: {}, value: {}}}", status, value)
                }
                ServerValue::Node(m) => {
                    let parts: Vec<String> =
                        m.borrow().iter().map(|(k, v)| format!("{}: {}", k, v)).collect();
                    write!(f, "{{{}}}", parts.join(", "))
                }
                ServerValue::Content(inner) => write!(f, "{}", inner),
                ServerValue::Paged(_) => write!(f, "{{paged}}"),
                ServerValue::Redirect { location, status } => {
                    write!(f, "{{redirect: {}, status: {}}}", location, status)
                }
            },
            // Redacción de fondo: `secret(NAME)`, nunca el plaintext. Esto sella por
            // sí solo print/log/error/coerción-a-texto/contexto-LLM (todo pasa por
            // Display) — el plaintext no puede filtrarse por un `format!` accidental.
            SynValue::Secret(s) => write!(f, "{}", s),
            // Repr seguro y NO-lossy: `bytes(<hexlower>)`. Nunca decodifica a texto
            // (eso reintroduciría el lossy: G4). Sella print/text()/concat-con-texto.
            SynValue::Bytes(b) => write!(f, "{}", bytes_display(b)),
            // `re±imi` (estilo Python cmath): enteros sin `.0` (3+2i), fracción con
            // decimales (1.5-2i). El signo lo da la parte imaginaria.
            SynValue::Complex(z) => write!(f, "{}", complex_display(z.re, z.im)),
            // Repr anidado estilo NumPy; ACOTADO a un resumen si size > 100.
            SynValue::Array(a) => write!(f, "{}", array_display(a)),
        }
    }
}

/// Repr anidado de un array estilo NumPy (`[1, 2, 3]` / `[[1, 2], [3, 4]]`). Reusa el
/// recorte de `.0` de los floats (enteros sin decimal). **Acotado**: si hay más de 100
/// elementos, muestra un resumen `array(shape=[..], N elements)` (no vuelca millones).
pub fn array_display(a: &ArrayD<f64>) -> String {
    if a.len() > 100 {
        let shape: Vec<String> = a.shape().iter().map(|d| d.to_string()).collect();
        return format!("array(shape=[{}], {} elements)", shape.join(", "), a.len());
    }
    fn rec(a: &ndarray::ArrayViewD<f64>) -> String {
        if a.ndim() == 0 {
            trim_float(*a.first().unwrap())
        } else {
            let parts: Vec<String> = a.outer_iter().map(|s| rec(&s)).collect();
            format!("[{}]", parts.join(", "))
        }
    }
    rec(&a.view())
}

/// Float al estilo del lenguaje pero recortando un `.0` final (como el repr de Python
/// dentro de complejos: `3.0`→`"3"`, `1.5`→`"1.5"`, `nan`/`inf` intactos).
fn trim_float(x: f64) -> String {
    let s = py_float_str(x);
    s.strip_suffix(".0").map(|t| t.to_string()).unwrap_or(s)
}

/// Repr de un complejo: `<re><±><|im|>i` (p.ej. `3+2i`, `3-2i`, `0+1i`). El signo es el
/// de la parte imaginaria.
pub fn complex_display(re: f64, im: f64) -> String {
    let sign = if im < 0.0 { '-' } else { '+' };
    format!("{}{}{}i", trim_float(re), sign, trim_float(im.abs()))
}

/// Repr textual seguro de unos bytes para `Display`: `bytes(<hexlower>)`. Para más de
/// 32 bytes, muestra los primeros 32 en hex + `…` + ` (<n> bytes)`. **Nunca** decodifica
/// a texto (no-lossy, G4) — así `print`/`text()`/concat muestran el hex, no datos crudos.
pub fn bytes_display(b: &[u8]) -> String {
    if b.len() > 32 {
        format!("bytes({}… ({} bytes))", crate::bytesutil::hex_encode(&b[..32]), b.len())
    } else {
        format!("bytes({})", crate::bytesutil::hex_encode(b))
    }
}

impl fmt::Debug for SynValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SynValue({}: {})", self.type_name(), self)
    }
}

// -- Constructores de conveniencia --

pub fn syn_number(n: Number) -> SynValue {
    SynValue::Number(n)
}
pub fn syn_int(n: i64) -> SynValue {
    SynValue::Number(Number::Int(n))
}
pub fn syn_float(x: f64) -> SynValue {
    SynValue::Number(Number::Float(x))
}
pub fn syn_text(s: impl Into<Rc<str>>) -> SynValue {
    SynValue::Text(s.into())
}
pub fn syn_bool(b: bool) -> SynValue {
    SynValue::Bool(b)
}
pub fn syn_nothing() -> SynValue {
    SynValue::Nothing
}
pub fn syn_list(items: Vec<SynValue>) -> SynValue {
    SynValue::List(Rc::new(RefCell::new(items)))
}
pub fn syn_map(m: IndexMap<String, SynValue>) -> SynValue {
    SynValue::Map(Rc::new(RefCell::new(m)))
}
/// Construye un `secret` opaco a partir de su nombre de origen y su plaintext.
pub fn syn_secret(name: impl Into<String>, plaintext: impl Into<String>) -> SynValue {
    SynValue::Secret(Rc::new(SecretInner::new(name, plaintext)))
}
/// Construye un `secret` opaco de BYTES (blob binario sellado con `as_secret`).
pub fn syn_secret_bytes(name: impl Into<String>, bytes: Vec<u8>) -> SynValue {
    SynValue::Secret(Rc::new(SecretInner::new_bytes(name, bytes)))
}
/// Construye un valor `bytes` (inmutable). Acepta `Vec<u8>` → `Rc<[u8]>` vía `Into`.
pub fn syn_bytes(b: impl Into<Rc<[u8]>>) -> SynValue {
    SynValue::Bytes(b.into())
}
/// Construye un `complex` a partir de sus partes real e imaginaria.
pub fn syn_complex(re: f64, im: f64) -> SynValue {
    SynValue::Complex(Complex64::new(re, im))
}
/// Construye un `array` (envuelve el `ArrayD<f64>` en `Rc`, inmutable compartido).
pub fn syn_array(a: ArrayD<f64>) -> SynValue {
    SynValue::Array(Rc::new(a))
}

// =========================================================
// SendValue — representación owned, `Send`+`Sync`, para cruzar hilos
// =========================================================
//
// `SynValue` usa `Rc`/`RefCell` (no es `Send`), así que NO puede compartirse entre
// hilos. Los agentes corren en hilos reales y se comunican por el blackboard con
// paso de mensajes (modelo CSP, sin memoria mutable compartida): al `share` se hace
// una **copia/snapshot** a `SendValue`, y al `observe` se reconstruye un `SynValue`
// nuevo en el intérprete del agente. Esto da semántica de copia (no aliasing entre
// agentes), alineado con el plan.

/// Valor owned y thread-safe (snapshot de un `SynValue`).
#[derive(Clone, Debug, PartialEq)]
pub enum SendValue {
    Number(Number),
    Text(String),
    Bool(bool),
    Nothing,
    List(Vec<SendValue>),
    Map(Vec<(String, SendValue)>),
    /// Snapshot binario (feature `bytes`): cruza el blackboard como copia owned (G7).
    Bytes(Vec<u8>),
    /// Snapshot de un complejo (re, im): cruza el blackboard como copia owned (G7).
    Complex(f64, f64),
    /// Snapshot de un array (shape, datos row-major): cruza el blackboard como copia (G7).
    Array(Vec<usize>, Vec<f64>),
}

/// Snapshot de un `SynValue` a `SendValue` (deep copy). Task/Builtin no cruzan: se
/// degradan a su texto (no se comparten closures entre hilos).
pub fn to_send(v: &SynValue) -> SendValue {
    match v {
        SynValue::Number(n) => SendValue::Number(n.clone()),
        SynValue::Text(s) => SendValue::Text(s.to_string()),
        SynValue::Bool(b) => SendValue::Bool(*b),
        SynValue::Nothing => SendValue::Nothing,
        SynValue::List(l) => SendValue::List(l.borrow().iter().map(to_send).collect()),
        SynValue::Map(m) => {
            SendValue::Map(m.borrow().iter().map(|(k, v)| (k.clone(), to_send(v))).collect())
        }
        SynValue::Task(_) | SynValue::Builtin(_) => SendValue::Text(v.to_string()),
        // Los valores del servidor casi nunca cruzan el blackboard; se degradan a
        // un snapshot map-like (o texto para paged).
        SynValue::Server(s) => match &**s {
            ServerValue::Raw { body, content_type, status } => SendValue::Map(vec![
                ("body".to_string(), SendValue::Text(body.clone())),
                ("content_type".to_string(), SendValue::Text(content_type.clone())),
                ("status".to_string(), SendValue::Number(Number::Int(*status))),
            ]),
            ServerValue::RawBytes { body, content_type, status } => SendValue::Map(vec![
                ("body".to_string(), SendValue::Bytes(body.clone())),
                ("content_type".to_string(), SendValue::Text(content_type.clone())),
                ("status".to_string(), SendValue::Number(Number::Int(*status))),
            ]),
            ServerValue::Envelope { status, value } => SendValue::Map(vec![
                ("status".to_string(), SendValue::Number(Number::Int(*status))),
                ("value".to_string(), to_send(value)),
            ]),
            ServerValue::Node(m) => {
                SendValue::Map(m.borrow().iter().map(|(k, v)| (k.clone(), to_send(v))).collect())
            }
            ServerValue::Content(inner) => to_send(inner),
            ServerValue::Paged(_) => SendValue::Text("{paged}".to_string()),
            ServerValue::Redirect { location, status } => SendValue::Map(vec![
                ("redirect".to_string(), SendValue::Text(location.clone())),
                ("status".to_string(), SendValue::Number(Number::Int(*status))),
            ]),
        },
        // Blackboard entre agentes (#6): el secret se **redacta** al compartir. Un
        // agente comprometido no puede `share` el plaintext — del otro lado se observa
        // un texto redactado, no un secret reconstruible.
        SynValue::Secret(s) => SendValue::Text(s.to_string()),
        // Snapshot binario (copia owned, sin aliasing): G7.
        SynValue::Bytes(b) => SendValue::Bytes(b.to_vec()),
        // Snapshot del complejo (re, im): copia owned (G7).
        SynValue::Complex(z) => SendValue::Complex(z.re, z.im),
        // Snapshot del array (shape + datos row-major): copia owned (G7).
        SynValue::Array(a) => SendValue::Array(a.shape().to_vec(), a.iter().copied().collect()),
    }
}

/// Reconstruye un `SynValue` (nuevo) desde un `SendValue`.
pub fn from_send(v: &SendValue) -> SynValue {
    match v {
        SendValue::Number(n) => SynValue::Number(n.clone()),
        SendValue::Text(s) => syn_text(s.as_str()),
        SendValue::Bool(b) => SynValue::Bool(*b),
        SendValue::Nothing => SynValue::Nothing,
        SendValue::List(items) => syn_list(items.iter().map(from_send).collect()),
        SendValue::Map(pairs) => {
            let mut m = IndexMap::new();
            for (k, v) in pairs {
                m.insert(k.clone(), from_send(v));
            }
            syn_map(m)
        }
        SendValue::Bytes(v) => syn_bytes(v.clone()),
        SendValue::Complex(re, im) => syn_complex(*re, *im),
        // Reconstruye el array desde shape + datos. Si la shape no cuadra con los datos
        // (no debería: el snapshot es consistente), cae a un array 1D con los datos.
        SendValue::Array(shape, data) => {
            match ArrayD::from_shape_vec(ndarray::IxDyn(shape), data.clone()) {
                Ok(a) => syn_array(a),
                Err(_) => syn_array(ArrayD::from_shape_vec(ndarray::IxDyn(&[data.len()]), data.clone()).unwrap()),
            }
        }
    }
}

impl fmt::Display for SendValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendValue::Nothing => write!(f, "nothing"),
            SendValue::Bool(b) => write!(f, "{}", if *b { "true" } else { "false" }),
            SendValue::Number(n) => write!(f, "{}", n),
            SendValue::Text(s) => write!(f, "{}", s),
            SendValue::List(items) => {
                let parts: Vec<String> = items.iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", parts.join(", "))
            }
            SendValue::Map(pairs) => {
                let parts: Vec<String> =
                    pairs.iter().map(|(k, v)| format!("{}: {}", k, v)).collect();
                write!(f, "{{{}}}", parts.join(", "))
            }
            // Espeja el repr hex de `SynValue::Bytes` (mismo `bytes(<hex>)`).
            SendValue::Bytes(b) => write!(f, "{}", bytes_display(b)),
            // Mismo formato `re±imi` que `SynValue::Complex`.
            SendValue::Complex(re, im) => write!(f, "{}", complex_display(*re, *im)),
            // Reconstruye el array y reusa el repr NumPy-like.
            SendValue::Array(shape, data) => {
                match ArrayD::from_shape_vec(ndarray::IxDyn(shape), data.clone()) {
                    Ok(a) => write!(f, "{}", array_display(&a)),
                    Err(_) => write!(f, "array(shape=[{}])", shape.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ")),
                }
            }
        }
    }
}

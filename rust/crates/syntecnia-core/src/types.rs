//! Modelo de valores de Syntecnia.
//!
//! Port de `syntecnia/core/types.py`. En Python todo valor es un `SynValue` que
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

use crate::ast::Node;
use crate::interpreter::{BuiltinTask, Environment};
use crate::number::Number;
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
}

/// Closure de paginación lazy de `paged()`: `fetch(limit, offset) → (filas, total)`.
/// `limit = None` materializa todo. Devuelve Err con mensaje si la query falla.
pub type PagedFetch = dyn Fn(Option<i64>, i64) -> Result<(Vec<SynValue>, i64), String>;

/// Variantes de valor del servidor (cada una lleva un tag implícito por su variante).
pub enum ServerValue {
    /// `html()`/`respond()`/`render()` — body escrito verbatim. (_RAW)
    Raw { body: String, content_type: String, status: i64 },
    /// `ok()`/`created()`/`not_found()`/`fail()` — status + valor interno. (_ENVELOPE)
    Envelope { status: i64, value: SynValue },
    /// Nodo de contenido (`heading`/`prose`/`list`/…): map `{kind, …}`. (_NODE)
    Node(MapRef),
    /// `content()` — árbol negociable (HTML/MD/JSON). Envuelve un nodo. (_CONTENT)
    Content(Box<SynValue>),
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
            ServerValue::Envelope { status, value } => match key {
                "status" => Some(syn_int(*status)),
                "value" => Some(value.clone()),
                _ => None,
            },
            ServerValue::Node(m) => m.borrow().get(key).cloned(),
            ServerValue::Content(_) | ServerValue::Paged(_) => None,
        }
    }
}

/// Un task definido por el usuario, con su entorno de cierre (closure).
pub struct SynTaskValue {
    pub name: String,
    pub parameters: Vec<String>,
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
            SynValue::Number(_) => "number",
            SynValue::Text(_) => "text",
            SynValue::Bool(_) => "bool",
            SynValue::Nothing => "nothing",
            SynValue::List(_) => "list",
            SynValue::Map(_) => "map",
            SynValue::Task(_) | SynValue::Builtin(_) => "task",
            // type=SynMap() en el oráculo para todos los valores del servidor.
            SynValue::Server(_) => "map",
        }
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
        }
    }

    /// Igualdad por valor (operador `==`/`!=`, `match`, `contains`).
    pub fn syn_equals(&self, other: &SynValue) -> bool {
        match (self, other) {
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
                _ => false,
            },
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
            SynValue::Task(t) => write!(f, "task {}({})", t.name, t.parameters.join(", ")),
            SynValue::Builtin(b) => write!(f, "builtin:{}", b.name),
            // str() de un valor del servidor: repr map-like de su dict subyacente.
            SynValue::Server(s) => match &**s {
                ServerValue::Raw { body, content_type, status } => write!(
                    f,
                    "{{body: {}, content_type: {}, status: {}}}",
                    body, content_type, status
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
            },
        }
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
            ServerValue::Envelope { status, value } => SendValue::Map(vec![
                ("status".to_string(), SendValue::Number(Number::Int(*status))),
                ("value".to_string(), to_send(value)),
            ]),
            ServerValue::Node(m) => {
                SendValue::Map(m.borrow().iter().map(|(k, v)| (k.clone(), to_send(v))).collect())
            }
            ServerValue::Content(inner) => to_send(inner),
            ServerValue::Paged(_) => SendValue::Text("{paged}".to_string()),
        },
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
        }
    }
}

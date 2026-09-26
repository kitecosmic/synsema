//! El resolver (F3.0 de specs/compute-rendimiento.md): un pase sobre el AST que dice, para cada
//! variable que se lee, se escribe o se liga, en qué scope vive y en qué posición de su frame.
//! Lo lee el compilador de la VM (F3); **el tree-walker no lo usa**: sigue buscando por nombre,
//! que es lo que le conviene a la referencia. Nada de esto cambia qué hace un programa.
//!
//! Qué es un scope acá: cada frame que el intérprete abre dentro de un programa —una llamada
//! (`call`), una vuelta de `each`, un brazo de `match`, el `recover` de un `try`, un `sandbox`—.
//! `when`, `while` y el cuerpo de un `try` NO abren frame: un `let` adentro liga en el frame de
//! afuera, y sólo si esa rama corre. Por eso un scope conoce todos los nombres que *puede* ligar
//! (`names`, en orden de aparición, los parámetros primero) pero no todos están siempre: un slot
//! vacío es "no está acá" y la búsqueda sigue hacia afuera, igual que hoy (`Bindings::get` salta
//! los huecos). Lo que el resolver sí prueba es cuándo un nombre está ligado seguro (`definite`).
//!
//! La raíz de cada programa (el global, un módulo, un request de `serve`, un agente, un test) es
//! **dinámica**: el host y otras partes del motor le agregan nombres que el fuente no dice. Un
//! nombre que no está en ningún scope estático es `Free` y se busca por nombre.
//!
//! Además de resolver, deja lo que una VM y un JIT necesitan de entrada (§6.1 del spec):
//! - `escapes`: el frame puede sobrevivir a su llamada (lo captura una task o lambda interna, o
//!   un agente/ruta) o lo recorre por nombre código que la VM no compila.
//! - `opaque`: algo que el resolver no ve puede leer el frame por nombre (un brazo frío, el
//!   cuerpo de una ruta o de un agente, un hook). Si es opaco, todas sus variables tienen que
//!   estar en el `Environment`.
//! - `captured[k]`: la variable `k` la usa una task o lambda definida adentro.
//!   Una variable que no está capturada en un frame no opaco puede vivir en un registro.
//! - Los bucles (`loops`), para contar calor y, el día que haya JIT, reemplazar en medio del bucle.
//!
//! Las identidades de nodo son direcciones (`usize`) dentro del AST que se resolvió: sirven
//! mientras ese AST viva y nunca se desreferencian.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::{Node, NodeKind, Param, Program};

/// El tipo de frame que abre el intérprete para un scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    Call,
    Each,
    MatchArm,
    Recover,
    Sandbox,
}

impl ScopeKind {
    /// El nombre con el que el intérprete etiqueta ese frame (`EnvName::Static`).
    pub fn frame_name(self) -> &'static str {
        match self {
            ScopeKind::Call => "call",
            ScopeKind::Each => "each",
            ScopeKind::MatchArm => "match-arm",
            ScopeKind::Recover => "recover",
            ScopeKind::Sandbox => "sandbox",
        }
    }
}

pub type ScopeId = u32;
pub type UnitId = u32;

#[derive(Debug)]
pub struct Scope {
    pub kind: ScopeKind,
    /// El scope de afuera; `None` = la raíz dinámica del programa.
    pub parent: Option<ScopeId>,
    /// La unidad (programa, task, lambda, cuerpo suelto) a la que pertenece.
    pub unit: UnitId,
    /// Los nombres que este scope puede ligar, en el orden del frame: parámetros (o la variable
    /// del `each`, el error del `recover`, los binders del patrón) y después cada nombre nuevo
    /// en el orden en que aparece en el fuente.
    pub names: Vec<Arc<str>>,
    /// Por nombre: lo lee o escribe una task o lambda definida adentro.
    pub captured: Vec<bool>,
    pub escapes: bool,
    pub opaque: bool,
    /// Un hook (`serve`, agentes, `spawn`) recibe este frame y puede ligar nombres que el
    /// fuente no dice: nada se resuelve a este scope ni a través de él.
    pub dynamic: bool,
}

impl Scope {
    pub fn slot_of(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| &**n == name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitKind {
    /// El programa (o un módulo): corre en la raíz dinámica.
    Program,
    Task,
    Lambda,
    /// Un cuerpo que el motor corre en otra raíz dinámica: una ruta, un agente, un test, un
    /// `socket`, el cuerpo de `reason`.
    Detached,
}

#[derive(Debug)]
pub struct Unit {
    pub kind: UnitKind,
    /// El nodo que la define (el programa: 0).
    pub node: usize,
    /// El scope de llamada de una task o lambda; `None` para las que corren en una raíz.
    pub scope: Option<ScopeId>,
}

/// Dónde está una variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// En el slot `slot` del frame `depth` niveles hacia afuera (0 = el actual). Si no es
    /// `definite`, el slot puede estar vacío y entonces se sigue buscando por nombre.
    Slot { depth: u16, scope: ScopeId, slot: u16, definite: bool },
    /// En la raíz dinámica o más afuera: por nombre.
    Free,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Read,
    /// La raíz de un `set`.
    Write,
    /// Un `let` o la variable de un `each`.
    Bind,
}

#[derive(Debug)]
pub struct Access {
    pub node: usize,
    pub line: usize,
    pub column: usize,
    pub name: Arc<str>,
    pub kind: AccessKind,
    /// El scope donde se evalúa (`None` = la raíz).
    pub scope: Option<ScopeId>,
    pub target: Target,
}

#[derive(Debug)]
pub struct LoopInfo {
    pub node: usize,
    pub scope: Option<ScopeId>,
    pub is_each: bool,
}

#[derive(Debug, Default)]
pub struct Resolution {
    pub scopes: Vec<Scope>,
    pub units: Vec<Unit>,
    pub accesses: Vec<Access>,
    pub loops: Vec<LoopInfo>,
    /// Nodo → el scope que abre: `each`, brazo de `match`, `try` (su `recover`), `sandbox`, task
    /// o lambda (su llamada).
    pub opened: HashMap<usize, ScopeId>,
}

impl Resolution {
    /// Los accesos por dirección de nodo (lo que busca el compilador).
    pub fn by_node(&self) -> HashMap<usize, &Access> {
        self.accesses.iter().map(|a| (a.node, a)).collect()
    }
    /// El scope que abre un nodo.
    pub fn scope_opened_by(&self, node: &Node) -> Option<ScopeId> {
        self.opened.get(&addr(node)).copied()
    }
}

fn addr(n: &Node) -> usize {
    n as *const Node as usize
}

/// Resuelve un programa entero (con sus tasks, lambdas y cuerpos sueltos adentro).
pub fn resolve_program(program: &Program) -> Resolution {
    resolve_block(&program.statements)
}

/// Resuelve una lista de sentencias que corre en una raíz dinámica.
pub fn resolve_block(stmts: &[Node]) -> Resolution {
    let mut c = Collector::default();
    c.units.push(Unit { kind: UnitKind::Program, node: 0, scope: None });
    c.block(stmts, None, 0);
    let Collector { scopes, units, opened } = c;
    let mut r = Resolver { scopes, opened: &opened, accesses: Vec::new(), loops: Vec::new(), defs: Vec::new() };
    r.block(stmts, None);
    let Resolver { scopes, accesses, loops, .. } = r;
    Resolution { scopes, units, accesses, loops, opened }
}

// ---------------------------------------------------------------------------------------------
// Pase 1: los scopes, qué nombres puede ligar cada uno y qué escapa.
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Collector {
    scopes: Vec<Scope>,
    units: Vec<Unit>,
    /// Nodo → scope que abre.
    opened: HashMap<usize, ScopeId>,
}

impl Collector {
    fn new_scope(&mut self, kind: ScopeKind, parent: Option<ScopeId>, unit: UnitId) -> ScopeId {
        self.scopes.push(Scope {
            kind,
            parent,
            unit,
            names: Vec::new(),
            captured: Vec::new(),
            escapes: false,
            opaque: false,
            dynamic: false,
        });
        (self.scopes.len() - 1) as ScopeId
    }

    fn new_unit(&mut self, kind: UnitKind, node: &Node, scope: Option<ScopeId>) -> UnitId {
        self.units.push(Unit { kind, node: addr(node), scope });
        (self.units.len() - 1) as UnitId
    }

    fn bind(&mut self, scope: Option<ScopeId>, name: &str) {
        if let Some(s) = scope {
            let sc = &mut self.scopes[s as usize];
            if sc.slot_of(name).is_none() {
                sc.names.push(Arc::from(name));
                sc.captured.push(false);
            }
        }
    }

    /// El frame y todos los de afuera sobreviven o se recorren por nombre desde afuera de la VM.
    fn mark_escape(&mut self, mut scope: Option<ScopeId>, opaque: bool) {
        while let Some(s) = scope {
            let sc = &mut self.scopes[s as usize];
            sc.escapes = true;
            sc.opaque |= opaque;
            scope = sc.parent;
        }
    }

    fn block(&mut self, stmts: &[Node], cur: Option<ScopeId>, unit: UnitId) {
        for s in stmts {
            self.node(s, cur, unit);
        }
    }

    fn opt(&mut self, n: &Option<Box<Node>>, cur: Option<ScopeId>, unit: UnitId) {
        if let Some(n) = n {
            self.node(n, cur, unit);
        }
    }

    /// Una task o lambda: su scope de llamada, hijo del scope donde se define.
    #[allow(clippy::too_many_arguments)]
    fn function(
        &mut self,
        node: &Node,
        kind: UnitKind,
        params: &[Arc<str>],
        body: &[Node],
        cur: Option<ScopeId>,
        outer_unit: UnitId,
    ) {
        // La closure retiene el frame donde nace y todos los de afuera.
        self.mark_escape(cur, false);
        let unit = self.units.len() as UnitId;
        let s = self.new_scope(ScopeKind::Call, cur, unit);
        self.new_unit(kind, node, Some(s));
        self.opened.insert(addr(node), s);
        for p in params {
            self.bind(Some(s), p);
        }
        // Un `require` al tope del cuerpo se evalúa al definir, en el scope de afuera, y no queda
        // en el cuerpo (`exec_task_definition`).
        for stmt in body {
            match &stmt.kind {
                NodeKind::RequireStatement { scope, .. } if kind == UnitKind::Task => self.opt(scope, cur, outer_unit),
                _ => self.node(stmt, Some(s), unit),
            }
        }
    }

    /// Un cuerpo que corre en otra raíz dinámica, pero dentro de la cadena de este frame (una
    /// ruta, un agente): lo que haga por nombre puede tocar este frame.
    fn detached(&mut self, node: &Node, body: &[Node], cur: Option<ScopeId>) {
        self.mark_escape(cur, true);
        let unit = self.new_unit(UnitKind::Detached, node, None);
        self.block(body, None, unit);
    }

    fn node(&mut self, n: &Node, cur: Option<ScopeId>, unit: UnitId) {
        use NodeKind as K;
        // Lo que la VM no va a compilar corre en el tree-walker y busca por nombre. Definir una
        // task o una lambda sólo retiene el frame (`function`), salvo que la definición misma
        // evalúe algo en el tree-walker: los defaults (en cada llamada) y los `require`.
        let cold = match &n.kind {
            K::TaskDefinition { parameters, body, .. } => {
                parameters.iter().any(|p| p.default.is_some())
                    || body.iter().any(|s| matches!(s.kind, K::RequireStatement { .. }))
            }
            K::LambdaExpression { .. } => false,
            k => !is_hot(k),
        };
        if cold {
            self.mark_escape(cur, true);
        }
        match &n.kind {
            K::NumberLiteral { .. }
            | K::TextLiteral { .. }
            | K::BoolLiteral { .. }
            | K::NothingLiteral
            | K::Identifier { .. }
            | K::WildcardPattern
            | K::StateTransition { .. }
            | K::IntentDeclaration { .. }
            | K::PrivateClause
            | K::ExpectStatement { .. }
            | K::MatchArm { .. }
            | K::ListPattern { .. }
            | K::MapPattern { .. } => {}
            K::ListLiteral { elements } => self.block(elements, cur, unit),
            K::MapLiteral { pairs } => {
                for (k, v) in pairs {
                    self.node(k, cur, unit);
                    self.node(v, cur, unit);
                }
            }
            K::PropertyAccess { object, .. } => self.node(object, cur, unit),
            K::IndexAccess { object, index } => {
                self.node(object, cur, unit);
                self.node(index, cur, unit);
            }
            K::BinaryOp { left, right, .. } => {
                self.node(left, cur, unit);
                self.node(right, cur, unit);
            }
            K::CompareChain { operands, .. } => self.block(operands, cur, unit),
            K::UnaryOp { operand, .. } => self.node(operand, cur, unit),
            K::PipeExpression { value, transforms } => {
                self.node(value, cur, unit);
                self.block(transforms, cur, unit);
            }
            K::LetBinding { name, value, .. } => {
                self.node(value, cur, unit);
                self.bind(cur, name);
            }
            K::SetMutation { target, value } => {
                self.node(target, cur, unit);
                self.node(value, cur, unit);
            }
            K::WhenStatement { condition, body, otherwise, otherwise_when } => {
                self.node(condition, cur, unit);
                self.block(body, cur, unit);
                self.opt(otherwise_when, cur, unit);
                if let Some(o) = otherwise {
                    self.block(o, cur, unit);
                }
            }
            K::EachStatement { variable, collection, body } => {
                self.node(collection, cur, unit);
                let s = self.new_scope(ScopeKind::Each, cur, unit);
                self.opened.insert(addr(n), s);
                self.bind(Some(s), variable);
                self.block(body, Some(s), unit);
            }
            K::WhileStatement { condition, body } => {
                self.node(condition, cur, unit);
                self.block(body, cur, unit);
            }
            K::MatchStatement { value, arms, otherwise } => {
                self.node(value, cur, unit);
                for arm in arms {
                    let K::MatchArm { pattern, guard, body } = &arm.kind else { continue };
                    self.pattern_reads(pattern, cur, unit);
                    let s = self.new_scope(ScopeKind::MatchArm, cur, unit);
                    self.opened.insert(addr(arm), s);
                    let mut binders = Vec::new();
                    pattern_binders(pattern, &mut binders);
                    for b in &binders {
                        self.bind(Some(s), b);
                    }
                    self.opt(guard, Some(s), unit);
                    self.block(body, Some(s), unit);
                }
                if let Some(o) = otherwise {
                    self.block(o, cur, unit);
                }
            }
            K::StopStatement { value } => self.opt(value, cur, unit),
            K::TaskDefinition { name, parameters, body, .. } => {
                // Los defaults se evalúan en cada llamada, pero en el entorno donde se definió.
                for p in parameters {
                    if let Some(d) = &p.default {
                        self.node(d, cur, unit);
                    }
                }
                let names = param_names(parameters);
                self.function(n, UnitKind::Task, &names, body, cur, unit);
                self.bind(cur, name);
            }
            K::TaskCall { name, arguments } => {
                self.node(name, cur, unit);
                for a in arguments {
                    self.node(&a.value, cur, unit);
                }
            }
            K::LambdaExpression { parameters, body } => {
                self.function(n, UnitKind::Lambda, parameters, std::slice::from_ref(&**body), cur, unit);
            }
            K::GiveStatement { value } => self.opt(value, cur, unit),
            K::UseImport { alias, .. } => self.bind(cur, alias),
            K::ExportDeclaration { declaration } => self.node(declaration, cur, unit),
            K::TypeDefinition { name, .. } | K::EnumDefinition { name, .. } => self.bind(cur, name),
            K::AgentDefinition { name, capabilities, body, .. } => {
                self.block(capabilities, cur, unit);
                self.detached(n, body, cur);
                self.dynamic(cur);
                self.bind(cur, name);
            }
            K::SpawnStatement { arguments, .. } => {
                for (_, v) in arguments {
                    self.node(v, cur, unit);
                }
                self.dynamic(cur);
            }
            K::ShareStatement { value, key } => {
                self.node(value, cur, unit);
                self.node(key, cur, unit);
            }
            K::ObserveStatement { key, variable } => {
                self.node(key, cur, unit);
                self.bind(cur, variable);
            }
            K::SignalStatement { name, data } => {
                self.node(name, cur, unit);
                self.opt(data, cur, unit);
            }
            K::WaitForStatement { signal_name, variable, timeout } => {
                self.node(signal_name, cur, unit);
                self.opt(timeout, cur, unit);
                if let Some(v) = variable {
                    self.bind(cur, v);
                }
            }
            K::RequireStatement { scope, .. } => self.opt(scope, cur, unit),
            K::SandboxBlock { body, under } => {
                self.opt(under, cur, unit);
                let s = self.new_scope(ScopeKind::Sandbox, cur, unit);
                self.opened.insert(addr(n), s);
                self.block(body, Some(s), unit);
            }
            K::InvariantDeclaration { condition, .. } => self.node(condition, cur, unit),
            K::ApproveStatement { message, context, .. } => {
                self.node(message, cur, unit);
                self.opt(context, cur, unit);
            }
            K::ShowStatement { value, .. } => self.node(value, cur, unit),
            K::ConfirmStatement { message, .. } => self.node(message, cur, unit),
            K::AskExpression { prompt, options, .. } => {
                self.node(prompt, cur, unit);
                self.opt(options, cur, unit);
            }
            K::ReasonExpression { subject, context, body } => {
                self.opt(subject, cur, unit);
                for (_, v) in context {
                    self.node(v, cur, unit);
                }
                self.detached(n, body, cur);
            }
            K::DecideExpression { options, given, .. } => {
                self.opt(options, cur, unit);
                self.opt(given, cur, unit);
            }
            K::JudgeExpression { state, questions } => {
                self.node(state, cur, unit);
                for q in questions {
                    self.node(&q.instruction, cur, unit);
                    self.opt(&q.criteria, cur, unit);
                }
            }
            K::AnalyzeExpression { data, .. } => self.node(data, cur, unit),
            K::GenerateExpression { given, parameters, .. } => {
                self.opt(given, cur, unit);
                for (_, v) in parameters {
                    self.node(v, cur, unit);
                }
            }
            K::TraceBlock { body, .. } | K::MeasureBlock { body, .. } | K::StreamBlock { body } => {
                self.block(body, cur, unit)
            }
            K::LogStatement { message, .. } => self.node(message, cur, unit),
            K::CheckpointStatement { name } => self.node(name, cur, unit),
            K::TestBlock { body, .. } | K::SocketBlock { body } => self.detached(n, body, cur),
            K::TryRecover { try_body, error_variable, recover_body } => {
                self.block(try_body, cur, unit);
                let s = self.new_scope(ScopeKind::Recover, cur, unit);
                self.opened.insert(addr(n), s);
                self.bind(Some(s), error_variable);
                self.block(recover_body, Some(s), unit);
            }
            K::RouteDefinition { body, .. } => self.detached(n, body, cur),
            K::RoutesDeclaration { name, routes } => {
                for r in routes {
                    self.node(r, cur, unit);
                }
                self.bind(cur, name);
            }
            K::ServeBlock { routes, hosts, .. } => {
                for r in routes.iter().chain(hosts.iter()) {
                    self.node(r, cur, unit);
                }
                self.dynamic(cur);
            }
            K::HostBlock { routes, .. } => {
                for r in routes {
                    self.node(r, cur, unit);
                }
            }
            // Cláusulas de `serve`: las evalúa el runtime de serve, no se resuelven.
            K::TimeoutClause { .. }
            | K::RateLimitClause { .. }
            | K::ProxyStatement { .. }
            | K::SendStatement { .. }
            | K::MountClause { .. }
            | K::StaticMount { .. }
            | K::DescribeClause { .. } => {}
        }
    }

    fn dynamic(&mut self, cur: Option<ScopeId>) {
        if let Some(s) = cur {
            self.scopes[s as usize].dynamic = true;
        }
    }

    /// Las expresiones de un patrón se evalúan en el scope de AFUERA del brazo.
    fn pattern_reads(&mut self, p: &Node, cur: Option<ScopeId>, unit: UnitId) {
        visit_pattern_exprs(p, &mut |e| self.node(e, cur, unit));
    }
}

/// Cuántos nombres distintos hay (un parámetro repetido ocupa un solo slot).
fn distinct<'a>(names: impl Iterator<Item = &'a str>) -> usize {
    let mut seen: Vec<&str> = Vec::new();
    for n in names {
        if !seen.contains(&n) {
            seen.push(n);
        }
    }
    seen.len()
}

fn param_names(ps: &[Param]) -> Vec<Arc<str>> {
    ps.iter().map(|p| p.name.clone()).collect()
}

/// Lo que la VM compila; todo lo demás corre en el tree-walker (§6.0 punto 4).
fn is_hot(k: &NodeKind) -> bool {
    use NodeKind as K;
    matches!(
        k,
        K::NumberLiteral { .. }
            | K::TextLiteral { .. }
            | K::BoolLiteral { .. }
            | K::NothingLiteral
            | K::ListLiteral { .. }
            | K::MapLiteral { .. }
            | K::Identifier { .. }
            | K::PropertyAccess { .. }
            | K::IndexAccess { .. }
            | K::BinaryOp { .. }
            | K::CompareChain { .. }
            | K::UnaryOp { .. }
            | K::PipeExpression { .. }
            | K::LetBinding { .. }
            | K::SetMutation { .. }
            | K::WhenStatement { .. }
            | K::EachStatement { .. }
            | K::WhileStatement { .. }
            | K::MatchStatement { .. }
            | K::MatchArm { .. }
            | K::WildcardPattern
            | K::ListPattern { .. }
            | K::MapPattern { .. }
            | K::StopStatement { .. }
            | K::GiveStatement { .. }
            | K::TaskCall { .. }
            | K::CheckpointStatement { .. }
    )
}

/// Los nombres que liga un patrón de `match`, en el orden en que `match_pattern` los junta. A
/// nivel top un identificador suelto compara por valor, no liga (G2).
fn pattern_binders(p: &Node, out: &mut Vec<Arc<str>>) {
    use NodeKind as K;
    match &p.kind {
        K::WildcardPattern | K::ListPattern { .. } | K::MapPattern { .. } | K::PropertyAccess { .. } | K::TaskCall { .. } => {
            sub_binders(p, out)
        }
        _ => {}
    }
}

fn sub_binders(p: &Node, out: &mut Vec<Arc<str>>) {
    use NodeKind as K;
    match &p.kind {
        K::Identifier { name } => out.push(Arc::from(name.as_str())),
        K::ListPattern { prefix, rest, suffix } => {
            for e in prefix.iter().chain(suffix.iter()) {
                sub_binders(e, out);
            }
            if let Some(Some(name)) = rest {
                out.push(Arc::from(name.as_str()));
            }
        }
        K::MapPattern { fields } => {
            for (k, sub) in fields {
                match sub {
                    None => out.push(Arc::from(k.as_str())),
                    Some(s) => sub_binders(s, out),
                }
            }
        }
        K::TaskCall { name, arguments } => {
            if matches!(name.kind, K::PropertyAccess { .. }) && arguments.iter().all(|a| a.name.is_none()) {
                for a in arguments {
                    sub_binders(&a.value, out);
                }
            }
        }
        _ => {}
    }
}

/// Si un brazo que matchea liga SEGURO todos sus binders: sólo con patrones estructurales puros
/// (una variante de enum puede resultar ser una comparación por valor y no ligar nada).
fn pattern_binds_surely(p: &Node) -> bool {
    use NodeKind as K;
    match &p.kind {
        K::WildcardPattern | K::Identifier { .. } => true,
        K::ListPattern { prefix, suffix, .. } => prefix.iter().chain(suffix.iter()).all(pattern_binds_surely),
        K::MapPattern { fields } => fields.iter().all(|(_, s)| s.as_ref().is_none_or(pattern_binds_surely)),
        K::PropertyAccess { .. } | K::TaskCall { .. } => false,
        // Un literal no liga nada.
        _ => true,
    }
}

/// Las sub-expresiones de un patrón que el intérprete puede EVALUAR (en el scope de afuera): un
/// patrón de valor entero, el objeto de una variante, los argumentos de una llamada que no
/// resulta ser variante. Un identificador en posición de binder dentro de una lista o un mapa
/// nunca se evalúa.
fn visit_pattern_exprs(p: &Node, f: &mut dyn FnMut(&Node)) {
    use NodeKind as K;
    match &p.kind {
        K::WildcardPattern => {}
        K::ListPattern { prefix, suffix, .. } => {
            for e in prefix.iter().chain(suffix.iter()) {
                visit_sub_pattern_exprs(e, f);
            }
        }
        K::MapPattern { fields } => {
            for (_, s) in fields {
                if let Some(s) = s {
                    visit_sub_pattern_exprs(s, f);
                }
            }
        }
        // Top: todo lo demás se evalúa como valor (o como variante, que evalúa lo mismo).
        _ => f(p),
    }
}

fn visit_sub_pattern_exprs(p: &Node, f: &mut dyn FnMut(&Node)) {
    use NodeKind as K;
    match &p.kind {
        K::Identifier { .. } | K::WildcardPattern => {}
        K::ListPattern { .. } | K::MapPattern { .. } => visit_pattern_exprs(p, f),
        _ => f(p),
    }
}

// ---------------------------------------------------------------------------------------------
// Pase 2: cada acceso, con qué está ligado seguro en ese punto.
// ---------------------------------------------------------------------------------------------

struct Resolver<'a> {
    scopes: Vec<Scope>,
    opened: &'a HashMap<usize, ScopeId>,
    accesses: Vec<Access>,
    loops: Vec<LoopInfo>,
    /// Los scopes estáticos abiertos en este punto del recorrido (afuera → adentro), cada uno
    /// con qué slots están ligados seguro. Cruza unidades: una task anidada ve el estado del
    /// frame de afuera en el momento en que se define, que es un piso para cuando se la llame
    /// (un binding nunca se borra de un frame de scope estático).
    defs: Vec<(ScopeId, Vec<bool>)>,
}

impl Resolver<'_> {
    fn opened_by(&self, node: &Node) -> ScopeId {
        *self.opened.get(&addr(node)).expect("resolver: un nodo que el colector no vio")
    }

    fn top_mut(&mut self, cur: Option<ScopeId>) -> Option<&mut Vec<bool>> {
        match (self.defs.last_mut(), cur) {
            (Some((s, v)), Some(c)) if *s == c => Some(v),
            _ => None,
        }
    }

    fn snapshot(&mut self, cur: Option<ScopeId>) -> Option<Vec<bool>> {
        self.top_mut(cur).map(|v| v.clone())
    }

    fn restore(&mut self, cur: Option<ScopeId>, snap: &Option<Vec<bool>>) {
        if let (Some(v), Some(s)) = (self.top_mut(cur), snap) {
            v.clone_from(s);
        }
    }

    /// Después de dos ramas: ligado seguro sólo lo que quedó ligado en las dos.
    fn meet(&mut self, cur: Option<ScopeId>, other: &Option<Vec<bool>>) {
        if let (Some(v), Some(o)) = (self.top_mut(cur), other) {
            for (a, b) in v.iter_mut().zip(o.iter()) {
                *a = *a && *b;
            }
        }
    }

    fn push(&mut self, s: ScopeId, surely: usize) {
        let n = self.scopes[s as usize].names.len();
        let mut v = vec![false; n];
        for x in v.iter_mut().take(surely) {
            *x = true;
        }
        self.defs.push((s, v));
    }

    fn pop(&mut self) {
        self.defs.pop();
    }

    fn definite(&self, s: ScopeId, slot: usize) -> bool {
        self.defs.iter().rev().find(|(id, _)| *id == s).is_some_and(|(_, v)| v.get(slot).copied().unwrap_or(false))
    }

    fn lookup(&mut self, name: &str, from: Option<ScopeId>) -> Target {
        let origin_unit = from.map(|s| self.scopes[s as usize].unit);
        let mut depth: u16 = 0;
        let mut cur = from;
        while let Some(s) = cur {
            let sc = &self.scopes[s as usize];
            if sc.dynamic {
                return Target::Free;
            }
            if let Some(k) = sc.slot_of(name) {
                if Some(sc.unit) != origin_unit {
                    self.scopes[s as usize].captured[k] = true;
                }
                return Target::Slot { depth, scope: s, slot: k as u16, definite: self.definite(s, k) };
            }
            cur = sc.parent;
            depth = depth.saturating_add(1);
        }
        Target::Free
    }

    fn record(&mut self, node: &Node, name: &str, kind: AccessKind, cur: Option<ScopeId>) {
        let target = self.lookup(name, cur);
        self.accesses.push(Access {
            node: addr(node),
            line: node.location.line,
            column: node.location.column,
            name: Arc::from(name),
            kind,
            scope: cur,
            target,
        });
    }

    fn mark_bound(&mut self, cur: Option<ScopeId>, name: &str) {
        let Some(c) = cur else { return };
        let Some(k) = self.scopes[c as usize].slot_of(name) else { return };
        if let Some(v) = self.top_mut(cur) {
            v[k] = true;
        }
    }

    fn block(&mut self, stmts: &[Node], cur: Option<ScopeId>) {
        for s in stmts {
            self.node(s, cur);
        }
    }

    fn opt(&mut self, n: &Option<Box<Node>>, cur: Option<ScopeId>) {
        if let Some(n) = n {
            self.node(n, cur);
        }
    }

    fn function(&mut self, node: &Node, nparams: usize, body: &[Node], cur: Option<ScopeId>, is_task: bool) {
        let s = self.opened_by(node);
        for stmt in body {
            if let NodeKind::RequireStatement { scope, .. } = &stmt.kind {
                if is_task {
                    self.opt(scope, cur);
                }
            }
        }
        self.push(s, nparams);
        for stmt in body {
            if is_task && matches!(stmt.kind, NodeKind::RequireStatement { .. }) {
                continue;
            }
            self.node(stmt, Some(s));
        }
        self.pop();
    }

    fn detached(&mut self, body: &[Node]) {
        self.block(body, None);
    }

    fn set_target(&mut self, t: &Node, cur: Option<ScopeId>) {
        match &t.kind {
            NodeKind::Identifier { name } => self.record(t, name, AccessKind::Write, cur),
            NodeKind::PropertyAccess { object, .. } => self.set_target(object, cur),
            NodeKind::IndexAccess { object, index } => {
                self.set_target(object, cur);
                self.node(index, cur);
            }
            _ => self.node(t, cur),
        }
    }

    fn node(&mut self, n: &Node, cur: Option<ScopeId>) {
        use NodeKind as K;
        match &n.kind {
            K::NumberLiteral { .. }
            | K::TextLiteral { .. }
            | K::BoolLiteral { .. }
            | K::NothingLiteral
            | K::WildcardPattern
            | K::StateTransition { .. }
            | K::IntentDeclaration { .. }
            | K::PrivateClause
            | K::ExpectStatement { .. }
            | K::MatchArm { .. }
            | K::ListPattern { .. }
            | K::MapPattern { .. } => {}
            K::Identifier { name } => self.record(n, name, AccessKind::Read, cur),
            K::ListLiteral { elements } => self.block(elements, cur),
            K::MapLiteral { pairs } => {
                for (k, v) in pairs {
                    self.node(k, cur);
                    self.node(v, cur);
                }
            }
            K::PropertyAccess { object, .. } => self.node(object, cur),
            K::IndexAccess { object, index } => {
                self.node(object, cur);
                self.node(index, cur);
            }
            K::BinaryOp { left, right, .. } => {
                self.node(left, cur);
                self.node(right, cur);
            }
            K::CompareChain { operands, .. } => self.block(operands, cur),
            K::UnaryOp { operand, .. } => self.node(operand, cur),
            K::PipeExpression { value, transforms } => {
                self.node(value, cur);
                self.block(transforms, cur);
            }
            K::LetBinding { name, value, .. } => {
                self.node(value, cur);
                self.mark_bound(cur, name);
                self.record(n, name, AccessKind::Bind, cur);
            }
            K::SetMutation { target, value } => {
                self.node(value, cur);
                self.set_target(target, cur);
            }
            K::WhenStatement { condition, body, otherwise, otherwise_when } => {
                self.node(condition, cur);
                let before = self.snapshot(cur);
                self.block(body, cur);
                let taken = self.snapshot(cur);
                self.restore(cur, &before);
                if let Some(ow) = otherwise_when {
                    self.node(ow, cur);
                } else if let Some(o) = otherwise {
                    self.block(o, cur);
                }
                self.meet(cur, &taken);
            }
            K::EachStatement { variable, collection, body } => {
                self.node(collection, cur);
                let s = self.opened_by(n);
                self.loops.push(LoopInfo { node: addr(n), scope: cur, is_each: true });
                self.push(s, 1);
                self.record(n, variable, AccessKind::Bind, Some(s));
                self.block(body, Some(s));
                self.pop();
            }
            K::WhileStatement { condition, body } => {
                self.loops.push(LoopInfo { node: addr(n), scope: cur, is_each: false });
                self.node(condition, cur);
                let before = self.snapshot(cur);
                self.block(body, cur);
                self.restore(cur, &before);
            }
            K::MatchStatement { value, arms, otherwise } => {
                self.node(value, cur);
                for arm in arms {
                    let K::MatchArm { pattern, guard, body } = &arm.kind else { continue };
                    visit_pattern_exprs(pattern, &mut |e| self.node(e, cur));
                    let s = self.opened_by(arm);
                    let surely = if pattern_binds_surely(pattern) { self.scopes[s as usize].names.len() } else { 0 };
                    self.push(s, surely);
                    self.opt(guard, Some(s));
                    self.block(body, Some(s));
                    self.pop();
                }
                if let Some(o) = otherwise {
                    let before = self.snapshot(cur);
                    self.block(o, cur);
                    self.restore(cur, &before);
                }
            }
            K::StopStatement { value } => self.opt(value, cur),
            K::TaskDefinition { name, parameters, body, .. } => {
                for p in parameters {
                    if let Some(d) = &p.default {
                        self.node(d, cur);
                    }
                }
                // El nombre queda ligado al terminar la definición, antes de que nadie pueda
                // llamarla: adentro del cuerpo (recursión) ya está.
                let nparams = distinct(parameters.iter().map(|p| &*p.name));
                self.mark_bound(cur, name);
                self.function(n, nparams, body, cur, true);
            }
            K::TaskCall { name, arguments } => {
                self.node(name, cur);
                for a in arguments {
                    self.node(&a.value, cur);
                }
            }
            K::LambdaExpression { parameters, body } => {
                let nparams = distinct(parameters.iter().map(|p| &**p));
                self.function(n, nparams, std::slice::from_ref(&**body), cur, false);
            }
            K::GiveStatement { value } => self.opt(value, cur),
            K::UseImport { alias, .. } => self.mark_bound(cur, alias),
            K::ExportDeclaration { declaration } => self.node(declaration, cur),
            K::TypeDefinition { name, .. } | K::EnumDefinition { name, .. } => self.mark_bound(cur, name),
            K::AgentDefinition { name, capabilities, body, .. } => {
                self.block(capabilities, cur);
                self.detached(body);
                self.mark_bound(cur, name);
            }
            K::SpawnStatement { arguments, .. } => {
                for (_, v) in arguments {
                    self.node(v, cur);
                }
            }
            K::ShareStatement { value, key } => {
                self.node(value, cur);
                self.node(key, cur);
            }
            K::ObserveStatement { key, variable } => {
                self.node(key, cur);
                self.mark_bound(cur, variable);
            }
            K::SignalStatement { name, data } => {
                self.node(name, cur);
                self.opt(data, cur);
            }
            K::WaitForStatement { signal_name, variable, timeout } => {
                self.node(signal_name, cur);
                self.opt(timeout, cur);
                if let Some(v) = variable {
                    self.mark_bound(cur, v);
                }
            }
            K::RequireStatement { scope, .. } => self.opt(scope, cur),
            K::SandboxBlock { body, under } => {
                self.opt(under, cur);
                let s = self.opened_by(n);
                self.push(s, 0);
                self.block(body, Some(s));
                self.pop();
            }
            K::InvariantDeclaration { condition, .. } => self.node(condition, cur),
            K::ApproveStatement { message, context, .. } => {
                self.node(message, cur);
                self.opt(context, cur);
            }
            K::ShowStatement { value, .. } => self.node(value, cur),
            K::ConfirmStatement { message, .. } => self.node(message, cur),
            K::AskExpression { prompt, options, .. } => {
                self.node(prompt, cur);
                self.opt(options, cur);
            }
            K::ReasonExpression { subject, context, body } => {
                self.opt(subject, cur);
                for (_, v) in context {
                    self.node(v, cur);
                }
                self.detached(body);
            }
            K::DecideExpression { options, given, .. } => {
                self.opt(options, cur);
                self.opt(given, cur);
            }
            K::JudgeExpression { state, questions } => {
                self.node(state, cur);
                for q in questions {
                    self.node(&q.instruction, cur);
                    self.opt(&q.criteria, cur);
                }
            }
            K::AnalyzeExpression { data, .. } => self.node(data, cur),
            K::GenerateExpression { given, parameters, .. } => {
                self.opt(given, cur);
                for (_, v) in parameters {
                    self.node(v, cur);
                }
            }
            K::TraceBlock { body, .. } | K::MeasureBlock { body, .. } | K::StreamBlock { body } => {
                self.block(body, cur)
            }
            K::LogStatement { message, .. } => self.node(message, cur),
            K::CheckpointStatement { name } => self.node(name, cur),
            K::TestBlock { body, .. } | K::SocketBlock { body } => self.detached(body),
            K::TryRecover { try_body, error_variable, recover_body } => {
                // Un error puede cortar el `try` en cualquier punto: después, nada de lo que
                // ligó es seguro.
                let before = self.snapshot(cur);
                self.block(try_body, cur);
                self.restore(cur, &before);
                let s = self.opened_by(n);
                let _ = error_variable;
                self.push(s, 1);
                self.block(recover_body, Some(s));
                self.pop();
            }
            K::RouteDefinition { body, .. } => self.detached(body),
            K::RoutesDeclaration { name, routes } => {
                for r in routes {
                    self.node(r, cur);
                }
                self.mark_bound(cur, name);
            }
            K::ServeBlock { routes, hosts, .. } => {
                for r in routes.iter().chain(hosts.iter()) {
                    self.node(r, cur);
                }
            }
            K::HostBlock { routes, .. } => {
                for r in routes {
                    self.node(r, cur);
                }
            }
            K::TimeoutClause { .. }
            | K::RateLimitClause { .. }
            | K::ProxyStatement { .. }
            | K::SendStatement { .. }
            | K::MountClause { .. }
            | K::StaticMount { .. }
            | K::DescribeClause { .. } => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Oráculo del resolver (sólo tests): mientras el tree-walker corre un programa, cada variable que
// busca por nombre se compara con lo que predijo el resolver. No existe en el binario: lo compila
// la feature `resolver-check`, que sólo prende `synsema-runtime` en sus dev-dependencies, y aun
// así hay que encenderlo (`check::set_enabled`) — lo hace `oracle_run --resolver-check`.
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "resolver-check")]
pub mod check {
    use super::{AccessKind, Resolution, ScopeId, Target};
    use crate::ast::Program;
    use crate::interpreter::Environment;
    use crate::tokens::SourceLocation;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    static ON: AtomicBool = AtomicBool::new(false);
    static STATE: Mutex<Option<State>> = Mutex::new(None);

    /// Lectura/escritura o ligadura: la raíz de un `set` también se evalúa como lectura en algunos
    /// caminos, así que las dos comparten clave.
    type Key = (usize, usize, Arc<str>, bool);

    #[derive(Default)]
    struct State {
        files: HashMap<Arc<str>, (Resolution, HashMap<Key, Option<usize>>)>,
        report: Report,
    }

    #[derive(Default, Debug, Clone)]
    pub struct Report {
        /// Accesos comparados.
        pub checked: u64,
        /// Accesos sin predicción (código que no vino de un programa resuelto: templates, el
        /// cuerpo de una lambda armado por el intérprete, nodos que comparten ubicación).
        pub unchecked: u64,
        pub violations: Vec<String>,
    }

    pub fn set_enabled(on: bool) {
        ON.store(on, Ordering::SeqCst);
    }

    pub fn enabled() -> bool {
        ON.load(Ordering::Relaxed)
    }

    pub fn take_report() -> Report {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        g.as_mut().map(|s| std::mem::take(&mut s.report)).unwrap_or_default()
    }

    /// Resuelve un programa (o un módulo) que está por correr.
    pub fn register(program: &Program) {
        if !enabled() {
            return;
        }
        let res = super::resolve_program(program);
        let mut index: HashMap<Key, Option<usize>> = HashMap::new();
        for (i, a) in res.accesses.iter().enumerate() {
            let key = (a.line, a.column, a.name.clone(), a.kind == AccessKind::Bind);
            match index.get(&key) {
                None => {
                    index.insert(key, Some(i));
                }
                Some(Some(j)) => {
                    let b = &res.accesses[*j];
                    if b.scope != a.scope || b.target != a.target {
                        index.insert(key, None);
                    }
                }
                Some(None) => {}
            }
        }
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        g.get_or_insert_with(State::default).files.insert(program.location.file.clone(), (res, index));
    }

    /// Una variable que el tree-walker está por buscar (o acaba de ligar) en `env`.
    pub fn at(loc: &SourceLocation, name: &str, bind: bool, env: &Rc<RefCell<Environment>>) {
        if !enabled() {
            return;
        }
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = g.as_mut() else { return };
        let key = (loc.line, loc.column, Arc::from(name), bind);
        let access = state.files.get(&loc.file).and_then(|(res, ix)| ix.get(&key).copied().flatten().map(|i| (res, i)));
        let Some((res, i)) = access else {
            state.report.unchecked += 1;
            return;
        };
        let a = &res.accesses[i];
        let problem = verify(res, a.scope, a.target, name, env);
        state.report.checked += 1;
        if let Some(p) = problem {
            if state.report.violations.len() < 50 {
                let v = format!("{}:{}:{} '{}': {}", loc.file, loc.line, loc.column, name, p);
                if !state.report.violations.contains(&v) {
                    state.report.violations.push(v);
                }
            }
        }
    }

    fn verify(
        res: &Resolution,
        scope: Option<ScopeId>,
        target: Target,
        name: &str,
        env: &Rc<RefCell<Environment>>,
    ) -> Option<String> {
        let mut chain = Vec::new();
        let mut s = scope;
        while let Some(id) = s {
            chain.push(id);
            s = res.scopes[id as usize].parent;
        }
        let mut frame = Some(env.clone());
        let mut found_at = None;
        let mut first_dynamic = chain.len();
        for (i, id) in chain.iter().enumerate() {
            let sc = &res.scopes[*id as usize];
            if sc.dynamic && first_dynamic == chain.len() {
                first_dynamic = i;
            }
            let Some(f) = frame else {
                return Some(format!("the resolver expected {} static frames, the chain has {}", chain.len(), i));
            };
            let e = f.borrow();
            if e.name.as_str() != sc.kind.frame_name() {
                return Some(format!(
                    "frame {} is '{}', the resolver expected '{}'",
                    i,
                    e.name.as_str(),
                    sc.kind.frame_name()
                ));
            }
            if !sc.dynamic {
                if let Some(k) = e.bindings.keys().find(|k| sc.slot_of(k).is_none()) {
                    return Some(format!(
                        "frame {} ('{}') binds '{}', which the resolver does not know for that scope",
                        i,
                        sc.kind.frame_name(),
                        k
                    ));
                }
            }
            if found_at.is_none() && e.bindings.get(name).is_some() {
                found_at = Some(i);
            }
            frame = e.parent.clone();
        }
        let ok = match target {
            Target::Slot { depth, definite, .. } => {
                let d = depth as usize;
                match found_at {
                    Some(i) => i == d || (i > d && !definite),
                    None => !definite,
                }
            }
            Target::Free => found_at.is_none_or(|i| i >= first_dynamic),
        };
        if ok {
            None
        } else {
            Some(format!("resolved to {:?}, found at frame {:?}", target, found_at))
        }
    }
}

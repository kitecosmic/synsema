//! Definiciones del AST de Synsema.
//!
//! Port fiel de `synsema/core/ast_nodes.py`. En Python cada nodo es una
//! dataclass que hereda de `Node` (lleva `location`). Acá modelamos eso como
//! `Node { location, kind }` con un `NodeKind` por cada dataclass. Los hijos
//! tipados dinámicamente en Python (p.ej. `arms`, `routes`) se guardan como
//! `Vec<Node>` del `NodeKind` esperado, igual de laxo que el oráculo.

use crate::tokens::{Number, SourceLocation};

/// Raíz del programa: secuencia de sentencias.
#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    pub location: SourceLocation,
    pub statements: Vec<Node>,
}

/// Un nodo del AST. Todos llevan `location` para observabilidad.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub location: SourceLocation,
    pub kind: NodeKind,
}

impl Node {
    pub fn new(location: SourceLocation, kind: NodeKind) -> Self {
        Self { location, kind }
    }

    /// Nombre, si este nodo es un `Identifier`.
    pub fn as_identifier(&self) -> Option<&str> {
        match &self.kind {
            NodeKind::Identifier { name } => Some(name),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NodeKind {
    // -- Literales --
    NumberLiteral {
        value: Number,
    },
    TextLiteral {
        value: String,
    },
    BoolLiteral {
        value: bool,
    },
    NothingLiteral,
    ListLiteral {
        elements: Vec<Node>,
    },
    MapLiteral {
        pairs: Vec<(Node, Node)>,
    },

    // -- Identificadores y acceso --
    Identifier {
        name: String,
    },
    /// `name of person` o `person.name`
    PropertyAccess {
        property_name: String,
        object: Box<Node>,
    },
    /// `list[0]` o `map["key"]`
    IndexAccess {
        object: Box<Node>,
        index: Box<Node>,
    },

    // -- Operadores --
    BinaryOp {
        left: Box<Node>,
        operator: String,
        right: Box<Node>,
    },
    UnaryOp {
        operator: String,
        operand: Box<Node>,
    },
    PipeExpression {
        value: Box<Node>,
        transforms: Vec<Node>,
    },

    // -- Bindings y mutación --
    LetBinding {
        name: String,
        value: Box<Node>,
        type_annotation: Option<String>,
    },
    SetMutation {
        target: Box<Node>,
        value: Box<Node>,
    },

    // -- Control de flujo --
    WhenStatement {
        condition: Box<Node>,
        body: Vec<Node>,
        otherwise: Option<Vec<Node>>,
        /// Encadenado `otherwise when ...` (es un WhenStatement).
        otherwise_when: Option<Box<Node>>,
    },
    EachStatement {
        variable: String,
        collection: Box<Node>,
        body: Vec<Node>,
    },
    WhileStatement {
        condition: Box<Node>,
        body: Vec<Node>,
    },
    MatchStatement {
        value: Box<Node>,
        arms: Vec<Node>, // cada uno es un MatchArm
    },
    MatchArm {
        pattern: Box<Node>,
        body: Vec<Node>,
    },
    StopStatement {
        value: Option<Box<Node>>,
    },

    // -- Definición de task (función) --
    TaskDefinition {
        name: String,
        parameters: Vec<String>,
        body: Vec<Node>,
        return_type: Option<String>,
        capabilities: Vec<String>,
    },
    TaskCall {
        name: Box<Node>, // Identifier o PropertyAccess
        arguments: Vec<Node>,
    },
    /// Función anónima de una sola expresión: `(params) => expr`.
    /// Evalúa a un valor función (tipo "task") que captura el entorno actual.
    LambdaExpression {
        parameters: Vec<String>,
        body: Box<Node>,
    },
    GiveStatement {
        value: Option<Box<Node>>,
    },

    // -- Módulos locales (import / export) --
    /// `use "./orders.syn" as orders` — importa un módulo local como un map de
    /// sus exports (sin tipo de runtime nuevo: property-access + call ya operan).
    UseImport {
        path: String,
        alias: String,
    },
    /// `export task f(...)` / `export type T` / `export let x be ...` — corre la
    /// definición y marca su nombre como parte de la superficie pública del módulo.
    ExportDeclaration {
        declaration: Box<Node>,
    },

    // -- Definición de tipo --
    TypeDefinition {
        name: String,
        fields: Vec<(String, String)>, // (nombre, tipo)
    },

    // -- Sistema de agentes --
    AgentDefinition {
        name: String,
        initial_state: Option<String>,
        capabilities: Vec<Node>,
        body: Vec<Node>,
    },
    SpawnStatement {
        agent_name: String,
        arguments: Vec<(String, Node)>, // preserva orden de inserción
    },
    ShareStatement {
        value: Box<Node>,
        key: Box<Node>,
    },
    ObserveStatement {
        key: Box<Node>,
        variable: String,
    },
    SignalStatement {
        name: String,
        data: Option<Box<Node>>,
    },
    WaitForStatement {
        signal_name: String,
        variable: Option<String>,
        timeout: Option<Box<Node>>,
    },
    StateTransition {
        new_state: String,
    },

    // -- Capacidades y seguridad --
    RequireStatement {
        capability: String,
        scope: Option<Box<Node>>,
    },
    SandboxBlock {
        body: Vec<Node>,
        allowed_capabilities: Vec<String>,
    },
    InvariantDeclaration {
        condition: Box<Node>,
        description: Option<String>,
    },
    IntentDeclaration {
        description: String,
    },

    // -- Interacción humana --
    ApproveStatement {
        message: Box<Node>,
        context: Option<Box<Node>>,
    },
    ShowStatement {
        value: Box<Node>,
        label: Option<String>,
    },
    ConfirmStatement {
        message: Box<Node>,
    },
    AskExpression {
        prompt: Box<Node>,
        options: Option<Box<Node>>,
    },

    // -- LLM / Razonamiento --
    ReasonExpression {
        subject: Option<Box<Node>>,
        context: Vec<(String, Node)>,
        body: Vec<Node>,
    },
    DecideExpression {
        options: Option<Box<Node>>,
        given: Option<Box<Node>>,
        criteria: Option<String>,
    },
    AnalyzeExpression {
        data: Box<Node>,
        objective: String,
    },
    GenerateExpression {
        target: String,
        given: Option<Box<Node>>,
        parameters: Vec<(String, Node)>,
    },

    // -- Observabilidad --
    TraceBlock {
        name: String,
        body: Vec<Node>,
    },
    LogStatement {
        message: Box<Node>,
        level: String,
    },
    MeasureBlock {
        name: String,
        body: Vec<Node>,
    },
    CheckpointStatement {
        name: String,
    },

    // -- Manejo de errores --
    TryRecover {
        try_body: Vec<Node>,
        error_variable: String,
        recover_body: Vec<Node>,
    },

    // -- Servidor HTTP --
    RouteDefinition {
        method: String,
        path: String,
        param_names: Vec<String>,
        requires_auth: bool,
        streaming: bool,
        rate_limit: Option<Box<Node>>, // RateLimitClause
        body: Vec<Node>,
    },
    StreamBlock {
        body: Vec<Node>,
    },
    /// Lote 2 — reverse proxy: `proxy to <url>` dentro de una route → forwardea.
    ProxyStatement {
        target: Box<Node>,
    },
    SendStatement {
        value: Box<Node>,
        event_name: Option<String>,
    },
    RateLimitClause {
        count: Option<Box<Node>>,
        window: String,
        unlimited: bool,
    },
    StaticMount {
        directory: Box<Node>,
        prefix: Option<Box<Node>>,
    },
    DescribeClause {
        about: Option<Box<Node>>,
        api: Option<Box<Node>>,
    },
    ServeBlock {
        port: Box<Node>,
        auth_handler: Option<Box<Node>>,
        max_body: Option<Box<Node>>,
        max_streams: Option<Box<Node>>,
        rate_limit: Option<Box<Node>>,
        static_mounts: Vec<Node>, // StaticMount
        cors: Option<Box<Node>>,
        describe: Option<Box<Node>>, // DescribeClause
        private: bool,
        routes: Vec<Node>, // RouteDefinition
        // A2 stack web: `tls cert <expr> key <expr>` + `redirect https`.
        tls_cert: Option<Box<Node>>,
        tls_key: Option<Box<Node>>,
        redirect_https: bool,
        // A2 batch 2 — ACME/auto-HTTPS: `tls auto [<email>]` + `domain <expr>`.
        tls_auto: bool,
        tls_auto_email: Option<Box<Node>>,
        domain: Option<Box<Node>>,
        // Lote 1 — vhost: bloques `host "..."` con su propia tabla (route/static/auth/tls).
        hosts: Vec<Node>, // HostBlock
    },
    /// vhost: `host "dominio"` (o `*.dominio`) con su propia tabla dentro de `serve`.
    HostBlock {
        pattern: Box<Node>,
        auth_handler: Option<Box<Node>>,
        static_mounts: Vec<Node>, // StaticMount
        routes: Vec<Node>,        // RouteDefinition
        tls_cert: Option<Box<Node>>,
        tls_key: Option<Box<Node>>,
    },
    ExpectStatement {
        target: String,
        shape: Vec<(String, String)>, // (campo, tipo)
    },
}

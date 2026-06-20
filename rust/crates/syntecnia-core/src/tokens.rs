//! Definiciones de tokens de Syntecnia.
//!
//! Port fiel de `syntecnia/core/tokens.py`. Los tokens son las unidades atómicas
//! del lenguaje y reflejan su filosofía: legible, plano, basado en intención.

use std::fmt;

/// Modelo numérico: re-exportado desde [`crate::number`].
/// `Int(i64)` fast-path · `Big(BigInt)` por promoción al desbordar i64 · `Float(f64)`.
/// Replica los enteros de precisión arbitraria de Python.
pub use crate::number::Number;

/// Tipos de token. Espeja `TokenType` del oráculo Python (mismos miembros).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenType {
    // -- Literales --
    Number,
    Text,
    BoolTrue,
    BoolFalse,
    Nothing,
    Identifier,

    // -- Flujo --
    When,
    Otherwise,
    Each,
    While,
    Match,
    Is,
    Then,
    AndThen,
    Stop,
    Repeat,
    In,
    With,

    // -- Definiciones --
    Task,
    Give,
    Let,
    Be,
    Set,
    To,
    As,
    Of,
    Type,

    // -- Agentes --
    Agent,
    Spawn,
    Share,
    Observe,
    State,
    Signal,
    WaitFor,

    // -- Capacidades y seguridad --
    Require,
    Allow,
    Deny,
    Sandbox,
    Verify,

    // -- Interacción humana --
    Approve,
    Show,
    Ask,
    Confirm,

    // -- Razonamiento (LLM) --
    Reason,
    Intent,
    Invariant,
    Decide,
    Analyze,
    Generate,

    // -- Manejo de errores --
    Try,
    Recover,

    // -- Soft keywords de servidor HTTP (NO están en KEYWORDS) --
    Serve,
    On,
    Route,
    Auth,
    Requires,
    Expect,
    MaxBody,
    Stream,
    Send,
    MaxStreams,
    RateLimit,
    Per,

    // -- Observabilidad --
    Trace,
    Log,
    Measure,
    Checkpoint,

    // -- Operadores --
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Power,
    Equal,
    NotEqual,
    Less,
    Greater,
    LessEqual,
    GreaterEqual,
    And,
    Or,
    Not,
    Assign,
    Arrow,
    FatArrow,
    Pipe,

    // -- Delimitadores --
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Dot,
    Colon,
    Newline,
    Indent,
    Dedent,

    // -- Especiales --
    Comment,
    Eof,
    Error,
}

impl TokenType {
    /// Nombre del miembro tal como lo expone Python (`TokenType.name`, en MAYÚS).
    /// Los mensajes de error del parser referencian estos nombres, así que son
    /// parte del contrato de paridad.
    pub fn name(&self) -> &'static str {
        use TokenType::*;
        match self {
            Number => "NUMBER",
            Text => "TEXT",
            BoolTrue => "BOOL_TRUE",
            BoolFalse => "BOOL_FALSE",
            Nothing => "NOTHING",
            Identifier => "IDENTIFIER",
            When => "WHEN",
            Otherwise => "OTHERWISE",
            Each => "EACH",
            While => "WHILE",
            Match => "MATCH",
            Is => "IS",
            Then => "THEN",
            AndThen => "AND_THEN",
            Stop => "STOP",
            Repeat => "REPEAT",
            In => "IN",
            With => "WITH",
            Task => "TASK",
            Give => "GIVE",
            Let => "LET",
            Be => "BE",
            Set => "SET",
            To => "TO",
            As => "AS",
            Of => "OF",
            Type => "TYPE",
            Agent => "AGENT",
            Spawn => "SPAWN",
            Share => "SHARE",
            Observe => "OBSERVE",
            State => "STATE",
            Signal => "SIGNAL",
            WaitFor => "WAIT_FOR",
            Require => "REQUIRE",
            Allow => "ALLOW",
            Deny => "DENY",
            Sandbox => "SANDBOX",
            Verify => "VERIFY",
            Approve => "APPROVE",
            Show => "SHOW",
            Ask => "ASK",
            Confirm => "CONFIRM",
            Reason => "REASON",
            Intent => "INTENT",
            Invariant => "INVARIANT",
            Decide => "DECIDE",
            Analyze => "ANALYZE",
            Generate => "GENERATE",
            Try => "TRY",
            Recover => "RECOVER",
            Serve => "SERVE",
            On => "ON",
            Route => "ROUTE",
            Auth => "AUTH",
            Requires => "REQUIRES",
            Expect => "EXPECT",
            MaxBody => "MAX_BODY",
            Stream => "STREAM",
            Send => "SEND",
            MaxStreams => "MAX_STREAMS",
            RateLimit => "RATE_LIMIT",
            Per => "PER",
            Trace => "TRACE",
            Log => "LOG",
            Measure => "MEASURE",
            Checkpoint => "CHECKPOINT",
            Plus => "PLUS",
            Minus => "MINUS",
            Star => "STAR",
            Slash => "SLASH",
            Percent => "PERCENT",
            Power => "POWER",
            Equal => "EQUAL",
            NotEqual => "NOT_EQUAL",
            Less => "LESS",
            Greater => "GREATER",
            LessEqual => "LESS_EQUAL",
            GreaterEqual => "GREATER_EQUAL",
            And => "AND",
            Or => "OR",
            Not => "NOT",
            Assign => "ASSIGN",
            Arrow => "ARROW",
            FatArrow => "FAT_ARROW",
            Pipe => "PIPE",
            LParen => "LPAREN",
            RParen => "RPAREN",
            LBracket => "LBRACKET",
            RBracket => "RBRACKET",
            LBrace => "LBRACE",
            RBrace => "RBRACE",
            Comma => "COMMA",
            Dot => "DOT",
            Colon => "COLON",
            Newline => "NEWLINE",
            Indent => "INDENT",
            Dedent => "DEDENT",
            Comment => "COMMENT",
            Eof => "EOF",
            Error => "ERROR",
        }
    }
}

/// Busca una palabra reservada (hard keyword). Las soft keywords del servidor HTTP
/// (`serve`, `on`, `route`, `auth`, `requires`, `expect`, etc.) **no** están acá:
/// el lexer las emite como `IDENTIFIER` y el parser las reconoce por contexto.
pub fn keyword_lookup(word: &str) -> Option<TokenType> {
    use TokenType::*;
    let ty = match word {
        // Flujo
        "when" => When,
        "otherwise" => Otherwise,
        "each" => Each,
        "while" => While,
        "match" => Match,
        "is" => Is,
        "then" => Then,
        "and_then" => AndThen,
        "stop" => Stop,
        "repeat" => Repeat,
        "in" => In,
        "with" => With,
        // Definiciones
        "task" => Task,
        "give" => Give,
        "let" => Let,
        "be" => Be,
        "set" => Set,
        "to" => To,
        "as" => As,
        "of" => Of,
        "type" => Type,
        // Agentes
        "agent" => Agent,
        "spawn" => Spawn,
        "share" => Share,
        "observe" => Observe,
        "state" => State,
        "signal" => Signal,
        "wait_for" => WaitFor,
        // Capacidades
        "require" => Require,
        "allow" => Allow,
        "deny" => Deny,
        "sandbox" => Sandbox,
        "verify" => Verify,
        // Humano
        "approve" => Approve,
        "show" => Show,
        "ask" => Ask,
        "confirm" => Confirm,
        // Razonamiento
        "reason" => Reason,
        "intent" => Intent,
        "invariant" => Invariant,
        "decide" => Decide,
        "analyze" => Analyze,
        "generate" => Generate,
        // Observabilidad
        "trace" => Trace,
        "log" => Log,
        "measure" => Measure,
        "checkpoint" => Checkpoint,
        // Manejo de errores
        "try" => Try,
        "recover" => Recover,
        // Literales
        "true" => BoolTrue,
        "false" => BoolFalse,
        "nothing" => Nothing,
        // Operadores lógicos
        "and" => And,
        "or" => Or,
        "not" => Not,
        _ => return None,
    };
    Some(ty)
}

/// Posición exacta en el código fuente, para reporte de errores y trazas.
/// `offset` cuenta code points (igual que el `pos` del lexer Python).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub offset: usize,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// Valor adjunto a un token. En Python `Token.value` es `Any`; acá lo modelamos
/// como enum según el tipo de token que lo produjo.
#[derive(Clone, Debug, PartialEq)]
pub enum TokenValue {
    /// Literal numérico (NUMBER).
    Number(Number),
    /// Texto: contenido de TEXT, nombre de IDENTIFIER/keyword, lexema de operador
    /// o delimitador, texto de COMMENT.
    Str(String),
    /// Nivel de indentación para INDENT/DEDENT.
    Int(i64),
    /// Sin valor (NEWLINE, EOF).
    None,
}

/// Un token del fuente Syntecnia. Cada token lleva su ubicación para trazabilidad.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub ty: TokenType,
    pub value: TokenValue,
    pub location: SourceLocation,
    /// Texto original del fuente que produjo este token.
    pub raw: String,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ty {
            TokenType::Newline | TokenType::Indent | TokenType::Dedent | TokenType::Eof => {
                write!(f, "Token({}, {})", self.ty.name(), self.location)
            }
            _ => write!(f, "Token({}, {}, {})", self.ty.name(), self.value_repr(), self.location),
        }
    }
}

impl Token {
    /// Contenido string del valor (IDENTIFIER/keyword/TEXT/operador). `""` si no aplica.
    pub fn as_str(&self) -> &str {
        match &self.value {
            TokenValue::Str(s) => s,
            _ => "",
        }
    }

    /// Valor numérico (NUMBER). `Int(0)` si no aplica.
    pub fn as_number(&self) -> Number {
        match &self.value {
            TokenValue::Number(n) => n.clone(),
            _ => Number::Int(0),
        }
    }

    /// Repr estilo Python de `value` (para Display/debug).
    fn value_repr(&self) -> String {
        match &self.value {
            TokenValue::Number(Number::Int(n)) => n.to_string(),
            TokenValue::Number(Number::Big(b)) => b.to_string(),
            TokenValue::Number(Number::Float(x)) => x.to_string(),
            TokenValue::Str(s) => format!("{:?}", s),
            TokenValue::Int(n) => n.to_string(),
            TokenValue::None => "None".to_string(),
        }
    }
}

//! Parser de Synsema — transforma tokens en AST.
//!
//! Port fiel de `synsema/core/parser.py`. Descenso recursivo con precedencia
//! por escalada para expresiones. Las soft keywords del servidor se reconocen
//! sólo al inicio de su construcción vía lookahead fijo. Los mensajes de error
//! son parte del contrato de paridad: se reproducen literalmente.

use std::fmt;

use crate::ast::{Arg, Node, NodeKind, Param, Program};
use crate::lexer::{Lexer, LexerError};
use crate::tokens::{
    keyword_lookup, Number, SourceLocation, TemplateSegment, Token, TokenType, TokenValue,
};

/// Error de parseo. `Display` = "file:line:col: mensaje".
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub location: SourceLocation,
}

impl ParseError {
    pub fn new(message: impl Into<String>, location: SourceLocation) -> Self {
        Self {
            message: message.into(),
            location,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Error de compilación: lexer o parser. Permite a la conveniencia `parse_source`
/// propagar ambos con el mismo `Display`.
#[derive(Debug, Clone)]
pub enum CompileError {
    Lex(LexerError),
    Parse(ParseError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::Lex(e) => write!(f, "{}", e),
            CompileError::Parse(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for CompileError {}

impl From<LexerError> for CompileError {
    fn from(e: LexerError) -> Self {
        CompileError::Lex(e)
    }
}

impl From<ParseError> for CompileError {
    fn from(e: ParseError) -> Self {
        CompileError::Parse(e)
    }
}

/// `repr()` de Python para un string: comillas simples salvo que el texto tenga
/// `'` y no `"` (entonces dobles), con escapes de backslash/comilla/controles.
fn py_repr_str(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr()` de Python para un float (los enteros exactos muestran `.0`).
fn py_float_repr(x: f64) -> String {
    if x.is_finite() && x == x.trunc() && x.abs() < 1e16 {
        format!("{:.1}", x)
    } else {
        format!("{}", x)
    }
}

/// `repr()` de Python para el valor de un token (usado en "Unexpected token").
fn token_value_repr(v: &TokenValue) -> String {
    match v {
        TokenValue::Number(Number::Int(n)) => n.to_string(),
        TokenValue::Number(Number::Big(b)) => b.to_string(),
        TokenValue::Number(Number::Float(x)) => py_float_repr(*x),
        TokenValue::Number(Number::Decimal(d)) => d.to_string(),
        TokenValue::Str(s) => py_repr_str(s),
        TokenValue::Int(n) => n.to_string(),
        // Un TEMPLATE siempre tiene su propio arm en parse_primary, así que nunca
        // llega al catch-all "Unexpected token": esto es inalcanzable en la práctica.
        TokenValue::Template(_) => "<template>".to_string(),
        TokenValue::None => "None".to_string(),
    }
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// >0 mientras se parsea dentro de un bloque `stream`.
    stream_depth: i64,
}

impl Parser {
    pub fn new(tokens: Vec<Token>, _filename: &str) -> Self {
        Self {
            tokens,
            pos: 0,
            stream_depth: 0,
        }
    }

    fn current(&self) -> &Token {
        if self.pos < self.tokens.len() {
            &self.tokens[self.pos]
        } else {
            &self.tokens[self.tokens.len() - 1] // EOF
        }
    }

    fn peek(&self, offset: usize) -> &Token {
        let idx = self.pos + offset;
        if idx < self.tokens.len() {
            &self.tokens[idx]
        } else {
            &self.tokens[self.tokens.len() - 1]
        }
    }

    fn at_end(&self) -> bool {
        self.current().ty == TokenType::Eof
    }

    fn advance(&mut self) -> Token {
        let tok = self.current().clone();
        self.pos += 1;
        tok
    }

    fn expect(&mut self, ty: TokenType, message: &str) -> Result<Token, ParseError> {
        if self.current().ty != ty {
            let cur = self.current();
            let msg = if message.is_empty() {
                format!("Expected {}, got {}", ty.name(), cur.ty.name())
            } else {
                message.to_string()
            };
            let loc = cur.location.clone();
            return Err(ParseError::new(msg, loc));
        }
        Ok(self.advance())
    }

    fn match_tok(&mut self, ty: TokenType) -> Option<Token> {
        if self.current().ty == ty {
            Some(self.advance())
        } else {
            None
        }
    }

    fn check(&self, ty: TokenType) -> bool {
        self.current().ty == ty
    }

    fn check_any(&self, types: &[TokenType]) -> bool {
        types.contains(&self.current().ty)
    }

    /// True si el token actual es un IDENTIFIER con este texto exacto (soft keyword).
    fn check_word(&self, word: &str) -> bool {
        let tok = self.current();
        tok.ty == TokenType::Identifier && tok.as_str() == word
    }

    fn peek_word(&self, offset: usize, word: &str) -> bool {
        let tok = self.peek(offset);
        tok.ty == TokenType::Identifier && tok.as_str() == word
    }

    /// True si el token en `offset` hace que una palabra soft del DSL se use como
    /// NOMBRE (identificador) en vez de como construcción: `(` `.` `[`, un operador
    /// binario, o `of` (acceso a propiedad). §3 de soft-dsl-keywords-spec.
    fn followed_by_name_use(&self, offset: usize) -> bool {
        matches!(
            self.peek(offset).ty,
            TokenType::LParen
                | TokenType::Dot
                | TokenType::LBracket
                | TokenType::Plus
                | TokenType::Minus
                | TokenType::Star
                | TokenType::Slash
                | TokenType::Percent
                | TokenType::Power
                | TokenType::Equal
                | TokenType::NotEqual
                | TokenType::Less
                | TokenType::Greater
                | TokenType::LessEqual
                | TokenType::GreaterEqual
                | TokenType::And
                | TokenType::Or
                | TokenType::Pipe
                | TokenType::Of
        )
    }

    /// True si la palabra soft del DSL `word` lidera aquí su construcción del DSL:
    /// es esa palabra Y no la sigue un token de uso-como-nombre. Si no, es un
    /// identificador ordinario (cae al camino de expresión). §3.
    fn soft_dsl(&self, word: &str) -> bool {
        self.check_word(word) && !self.followed_by_name_use(1)
    }

    fn expect_word(&mut self, word: &str, message: &str) -> Result<Token, ParseError> {
        if self.check_word(word) {
            return Ok(self.advance());
        }
        let msg = if message.is_empty() {
            format!("Expected '{}'", word)
        } else {
            message.to_string()
        };
        Err(ParseError::new(msg, self.current().location.clone()))
    }

    fn expect_name(&mut self, what: &str) -> Result<Token, ParseError> {
        let tok = self.current().clone();
        if tok.ty == TokenType::Identifier {
            return Ok(self.advance());
        }
        if keyword_lookup(&tok.raw).is_some() {
            return Err(ParseError::new(
                format!(
                    "'{}' is a reserved word in Synsema; choose another name for the {}",
                    tok.raw, what
                ),
                tok.location,
            ));
        }
        Err(ParseError::new(
            format!("Expected {}, got {}", what, tok.ty.name()),
            tok.location,
        ))
    }

    /// True si el valor (string) del token actual es igual a `s` (contextual words).
    fn current_value_eq(&self, s: &str) -> bool {
        matches!(&self.current().value, TokenValue::Str(v) if v == s)
    }

    fn skip_newlines(&mut self) {
        while self.current().ty == TokenType::Newline {
            self.advance();
        }
    }

    fn location(&self) -> SourceLocation {
        self.current().location.clone()
    }

    // =========================================================
    // Top-level
    // =========================================================

    pub fn parse(&mut self) -> Result<Program, ParseError> {
        let loc = self.location();
        let mut statements = Vec::new();
        self.skip_newlines();

        while !self.at_end() {
            if let Some(stmt) = self.parse_statement()? {
                statements.push(stmt);
            }
            self.skip_newlines();
        }

        Ok(Program { location: loc, statements })
    }

    // =========================================================
    // Statements
    // =========================================================

    fn parse_statement(&mut self) -> Result<Option<Node>, ParseError> {
        self.skip_newlines();
        if self.at_end() {
            return Ok(None);
        }

        // Soft keywords (lookahead fijo).
        if self.stream_depth > 0 && self.check_word("send") {
            return Ok(Some(self.parse_send()?));
        }
        if self.check_word("stream")
            && self.peek(1).ty == TokenType::Newline
            && self.peek(2).ty == TokenType::Indent
        {
            return Ok(Some(self.parse_stream()?));
        }
        if self.check_word("rate_limit")
            && (self.peek(1).ty == TokenType::Number
                || self.peek_word(1, "none")
                || self.peek_word(1, "unlimited"))
        {
            return Ok(Some(self.parse_rate_limit()?));
        }
        if self.check_word("serve") && self.peek_word(1, "on") {
            return Ok(Some(self.parse_serve()?));
        }
        if self.check_word("expect") && self.peek_word(1, "body") {
            return Ok(Some(self.parse_expect()?));
        }
        if self.check_word("proxy") && self.peek(1).ty == TokenType::To {
            return Ok(Some(self.parse_proxy()?));
        }
        // Módulos locales: `use "..." as name` y `export <task|type|let> ...`.
        if self.check_word("use") && self.peek(1).ty == TokenType::Text {
            return Ok(Some(self.parse_use()?));
        }
        // `enum` es soft keyword (Identifier con value "enum"), no un token type.
        if self.check_word("export")
            && (matches!(self.peek(1).ty, TokenType::Task | TokenType::Type | TokenType::Let)
                || self.peek_word(1, "enum"))
        {
            return Ok(Some(self.parse_export()?));
        }
        // Enums (sum types): `enum Name` liderando un statement, seguido de un NAME.
        if self.check_word("enum") && self.peek(1).ty == TokenType::Identifier {
            return Ok(Some(self.parse_enum()?));
        }
        // Test framework (Batch 3): `test "<nombre>"` lidera un bloque de test. SOFT
        // keyword: sólo se interpreta como tal si va seguido de un Text; en cualquier
        // otro lugar `test` es un identificador ordinario (G1).
        if self.check_word("test") && self.peek(1).ty == TokenType::Text {
            return Ok(Some(self.parse_test_block()?));
        }

        // DSL de features (agentes/human/observabilidad) — SOFT keywords: son su
        // construcción del DSL sólo si lideran el statement y no las sigue un token
        // de uso-como-nombre (`(`/`.`/`[`/operador/`of`); si no, caen a expresión. §3.
        if self.soft_dsl("agent") {
            return Ok(Some(self.parse_agent()?));
        }
        if self.soft_dsl("spawn") {
            return Ok(Some(self.parse_spawn()?));
        }
        if self.soft_dsl("share") {
            return Ok(Some(self.parse_share()?));
        }
        if self.soft_dsl("observe") {
            return Ok(Some(self.parse_observe()?));
        }
        if self.soft_dsl("signal") {
            return Ok(Some(self.parse_signal()?));
        }
        if self.soft_dsl("approve") {
            return Ok(Some(self.parse_approve()?));
        }
        if self.soft_dsl("show") {
            return Ok(Some(self.parse_show()?));
        }
        if self.soft_dsl("confirm") {
            return Ok(Some(self.parse_confirm()?));
        }
        if self.soft_dsl("trace") {
            return Ok(Some(self.parse_trace()?));
        }
        if self.soft_dsl("log") {
            return Ok(Some(self.parse_log()?));
        }
        if self.soft_dsl("measure") {
            return Ok(Some(self.parse_measure()?));
        }
        if self.soft_dsl("checkpoint") {
            return Ok(Some(self.parse_checkpoint()?));
        }

        let tt = self.current().ty;
        let node = match tt {
            TokenType::Let => self.parse_let()?,
            TokenType::Set => self.parse_set()?,
            TokenType::When => self.parse_when()?,
            TokenType::Each => self.parse_each()?,
            TokenType::While => self.parse_while()?,
            TokenType::Match => self.parse_match()?,
            TokenType::Task => self.parse_task_definition()?,
            TokenType::Give => self.parse_give()?,
            TokenType::Stop => self.parse_stop()?,
            TokenType::WaitFor => self.parse_wait_for()?,
            TokenType::Require => self.parse_require()?,
            TokenType::Sandbox => self.parse_sandbox()?,
            TokenType::Invariant => self.parse_invariant()?,
            TokenType::Intent => self.parse_intent()?,
            TokenType::Type => self.parse_type_definition()?,
            TokenType::Try => self.parse_try_recover()?,
            _ => self.parse_expression()?, // sentencia-expresión
        };
        Ok(Some(node))
    }

    fn parse_block(&mut self) -> Result<Vec<Node>, ParseError> {
        self.skip_newlines();
        self.expect(TokenType::Indent, "Expected indented block")?;
        let mut statements = Vec::new();

        self.skip_newlines();
        while !self.at_end() && !self.check(TokenType::Dedent) {
            if let Some(stmt) = self.parse_statement()? {
                statements.push(stmt);
            }
            self.skip_newlines();
        }

        if self.check(TokenType::Dedent) {
            self.advance();
        }

        Ok(statements)
    }

    // -- let / set --

    fn parse_let(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'let'
        let name_tok = self.expect_name("variable after 'let'")?;
        self.expect(TokenType::Be, "Expected 'be' after variable name in let binding")?;
        let value = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::LetBinding {
                name: name_tok.as_str().to_string(),
                value: Box::new(value),
                type_annotation: None,
            },
        ))
    }

    fn parse_set(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'set'
        let target = self.parse_expression()?;
        self.expect(TokenType::To, "Expected 'to' in set statement")?;
        let value = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::SetMutation {
                target: Box::new(target),
                value: Box::new(value),
            },
        ))
    }

    // -- when / otherwise --

    fn parse_when(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'when'
        let condition = self.parse_expression()?;

        // Forma inline: when <cond> then <expr> [otherwise [when ...] <expr>]
        // Usable en cualquier posición de expresión (map literal, apply, let, etc.).
        if self.match_tok(TokenType::Then).is_some() {
            let then_expr = self.parse_expression()?;
            let mut otherwise = None;
            let mut otherwise_when = None;
            if self.match_tok(TokenType::Otherwise).is_some() {
                self.skip_newlines();
                if self.check(TokenType::When) {
                    otherwise_when = Some(Box::new(self.parse_when()?));
                } else {
                    otherwise = Some(vec![self.parse_expression()?]);
                }
            }
            return Ok(Node::new(
                loc,
                NodeKind::WhenStatement {
                    condition: Box::new(condition),
                    body: vec![then_expr],
                    otherwise,
                    otherwise_when,
                },
            ));
        }

        // Forma de bloque (existente): when <cond>\n    body
        let body = self.parse_block()?;
        let mut otherwise = None;
        let mut otherwise_when = None;
        self.skip_newlines();
        if self.match_tok(TokenType::Otherwise).is_some() {
            self.skip_newlines();
            if self.check(TokenType::When) {
                otherwise_when = Some(Box::new(self.parse_when()?));
            } else {
                otherwise = Some(self.parse_block()?);
            }
        }
        Ok(Node::new(
            loc,
            NodeKind::WhenStatement {
                condition: Box::new(condition),
                body,
                otherwise,
                otherwise_when,
            },
        ))
    }

    // -- each --

    fn parse_each(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'each'
        let var_tok = self.expect_name("loop variable after 'each'")?;
        self.expect(TokenType::In, "Expected 'in' after variable in each loop")?;
        let collection = self.parse_expression()?;
        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::EachStatement {
                variable: var_tok.as_str().to_string(),
                collection: Box::new(collection),
                body,
            },
        ))
    }

    // -- while --

    fn parse_while(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let condition = self.parse_expression()?;
        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::WhileStatement {
                condition: Box::new(condition),
                body,
            },
        ))
    }

    // -- match --

    fn parse_match(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'match'
        let value = self.parse_expression()?;
        self.skip_newlines();
        self.expect(TokenType::Indent, "")?;
        let mut arms = Vec::new();

        self.skip_newlines();
        while self.check(TokenType::Is) {
            let arm_loc = self.location();
            self.advance(); // 'is'
            let pattern = self.parse_pattern()?;
            // Guard opcional `when <cond>`: se evalúa con los binders del patrón en scope.
            let guard = if self.match_tok(TokenType::When).is_some() {
                Some(Box::new(self.parse_expression()?))
            } else {
                None
            };
            let arm_body = self.parse_block()?;
            arms.push(Node::new(
                arm_loc,
                NodeKind::MatchArm {
                    pattern: Box::new(pattern),
                    guard,
                    body: arm_body,
                },
            ));
            self.skip_newlines();
        }

        // `otherwise` opcional (último, tras los arms `is`) — igual que en `when`.
        let mut otherwise = None;
        if self.match_tok(TokenType::Otherwise).is_some() {
            otherwise = Some(self.parse_block()?);
            self.skip_newlines();
        }

        if self.check(TokenType::Dedent) {
            self.advance();
        }

        Ok(Node::new(
            loc,
            NodeKind::MatchStatement {
                value: Box::new(value),
                arms,
                otherwise,
            },
        ))
    }

    /// Parsea un patrón de `match` (Batch 2). Las formas estructurales (wildcard `_`,
    /// list `[...]`, map `{...}`) producen nodos de patrón dedicados; cualquier otra
    /// cosa cae a `parse_expression()` (variante de enum, literal, bare-identifier como
    /// valor, etc. — comportamiento previo intacto). Recursivo: los sub-patrones dentro
    /// de list/map se parsean con `parse_pattern()`.
    fn parse_pattern(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        // `_` SOLO (no `_.foo` ni `_(...)`) → wildcard. Cualquier otro uso de `_` cae a
        // expresión (identificador ordinario).
        if self.check_word("_")
            && !matches!(self.peek(1).ty, TokenType::LParen | TokenType::Dot | TokenType::LBracket)
        {
            self.advance();
            return Ok(Node::new(loc, NodeKind::WildcardPattern));
        }
        if self.check(TokenType::LBracket) {
            return self.parse_list_pattern();
        }
        // `{...}` es un MAP PATTERN sólo si sus claves son identificadores bare (o `{}`
        // que matchea cualquier map). `{"k": 1}` (clave string/expr) es un map LITERAL →
        // patrón de valor por igualdad estructural (comportamiento previo intacto, G1).
        // Desambiguación por el primer token tras `{`.
        if self.check(TokenType::LBrace)
            && matches!(self.peek(1).ty, TokenType::RBrace | TokenType::Identifier)
        {
            return self.parse_map_pattern();
        }
        self.parse_expression()
    }

    /// `[a, b]` / `[h, ...rest]` / `[...init, last]` / `[a, ...mid, z]` / `[]`. Un solo
    /// spread (cero o uno); dos `...` → error de parseo.
    fn parse_list_pattern(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.expect(TokenType::LBracket, "")?;
        let mut prefix = Vec::new();
        let mut suffix = Vec::new();
        let mut rest: Option<Option<String>> = None;
        if !self.check(TokenType::RBracket) {
            loop {
                if self.check(TokenType::Spread) {
                    if rest.is_some() {
                        return Err(ParseError::new(
                            "a list pattern may have at most one '...' spread",
                            self.location(),
                        ));
                    }
                    self.advance(); // '...'
                    // Binder opcional inmediatamente después del spread: `...rest`.
                    if self.check(TokenType::Identifier) {
                        let name = self.advance().as_str().to_string();
                        rest = Some(Some(name));
                    } else {
                        rest = Some(None); // `...` anónimo
                    }
                } else {
                    let pat = self.parse_pattern()?;
                    if rest.is_some() {
                        suffix.push(pat);
                    } else {
                        prefix.push(pat);
                    }
                }
                if self.match_tok(TokenType::Comma).is_none() {
                    break;
                }
                if self.check(TokenType::RBracket) {
                    break; // coma final permitida
                }
            }
        }
        self.expect(TokenType::RBracket, "")?;
        Ok(Node::new(loc, NodeKind::ListPattern { prefix, rest, suffix }))
    }

    /// `{name, age}` (subset, bindea claves) / `{status: 200, body}` (clave : subpatrón)
    /// / `{}` (matchea cualquier map). Anidados vía `parse_pattern()` recursivo.
    fn parse_map_pattern(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.expect(TokenType::LBrace, "")?;
        let mut fields: Vec<(String, Option<Node>)> = Vec::new();
        if !self.check(TokenType::RBrace) {
            loop {
                let key = self.expect_name("map pattern field name")?.as_str().to_string();
                let subpat = if self.match_tok(TokenType::Colon).is_some() {
                    Some(self.parse_pattern()?)
                } else {
                    None
                };
                fields.push((key, subpat));
                if self.match_tok(TokenType::Comma).is_none() {
                    break;
                }
                if self.check(TokenType::RBrace) {
                    break; // coma final permitida
                }
            }
        }
        self.expect(TokenType::RBrace, "")?;
        Ok(Node::new(loc, NodeKind::MapPattern { fields }))
    }

    // -- módulos locales (use / export) --

    fn parse_use(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // soft keyword 'use'
        let path_tok = self.expect(TokenType::Text, "Expected a module path string after 'use'")?;
        self.expect(TokenType::As, "Expected 'as' after the module path")?;
        let alias_tok = self.expect_name("module alias after 'as'")?;
        Ok(Node::new(
            loc,
            NodeKind::UseImport {
                path: path_tok.as_str().to_string(),
                alias: alias_tok.as_str().to_string(),
            },
        ))
    }

    fn parse_export(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // soft keyword 'export'
        let decl = match self.current().ty {
            TokenType::Task => self.parse_task_definition()?,
            TokenType::Type => self.parse_type_definition()?,
            TokenType::Let => self.parse_let()?,
            // `enum` es soft keyword (Identifier con value "enum"), no un token type.
            _ if self.check_word("enum") => self.parse_enum()?,
            _ => {
                return Err(ParseError::new(
                    "export must be followed by task, type, let, or enum",
                    self.location(),
                ))
            }
        };
        Ok(Node::new(loc, NodeKind::ExportDeclaration { declaration: Box::new(decl) }))
    }

    // -- task --

    fn parse_task_definition(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'task'
        let name_tok = self.expect_name("task name")?;
        let mut params = Vec::new();

        if self.match_tok(TokenType::LParen).is_some() {
            if !self.check(TokenType::RParen) {
                params.push(self.parse_param()?);
                while self.match_tok(TokenType::Comma).is_some() {
                    params.push(self.parse_param()?);
                }
            }
            self.expect(TokenType::RParen, "")?;
        }

        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::TaskDefinition {
                name: name_tok.as_str().to_string(),
                parameters: params,
                body,
                return_type: None,
                capabilities: Vec::new(),
            },
        ))
    }

    /// Un parámetro de `task`: nombre y, tras `=`, un default opcional (Batch 2). El
    /// default se evalúa en call time (G5). `=` es `Assign` (distinto de `==`/`Equal`).
    fn parse_param(&mut self) -> Result<Param, ParseError> {
        let name = self.expect_name("parameter name")?.as_str().to_string();
        let default = if self.match_tok(TokenType::Assign).is_some() {
            Some(self.parse_expression()?)
        } else {
            None
        };
        Ok(Param { name, default })
    }

    fn parse_give(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let value = if !self.check_any(&[TokenType::Newline, TokenType::Dedent, TokenType::Eof]) {
            Some(Box::new(self.parse_expression()?))
        } else {
            None
        };
        Ok(Node::new(loc, NodeKind::GiveStatement { value }))
    }

    fn parse_stop(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let value = if !self.check_any(&[TokenType::Newline, TokenType::Dedent, TokenType::Eof]) {
            Some(Box::new(self.parse_expression()?))
        } else {
            None
        };
        Ok(Node::new(loc, NodeKind::StopStatement { value }))
    }

    // -- type --

    fn parse_type_definition(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'type'
        let name_tok = self.expect_name("type name")?;
        self.skip_newlines();
        self.expect(TokenType::Indent, "")?;
        let mut fields = Vec::new();

        self.skip_newlines();
        while !self.check_any(&[TokenType::Dedent, TokenType::Eof]) {
            let field_name = self.expect_name("field name")?.as_str().to_string();
            self.expect(TokenType::Colon, "")?;
            let type_name = self.expect(TokenType::Identifier, "")?.as_str().to_string();
            fields.push((field_name, type_name));
            self.skip_newlines();
        }

        if self.check(TokenType::Dedent) {
            self.advance();
        }

        Ok(Node::new(
            loc,
            NodeKind::TypeDefinition {
                name: name_tok.as_str().to_string(),
                fields,
            },
        ))
    }

    // -- enum (sum type) --

    fn parse_enum(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // soft keyword 'enum'
        let name_tok = self.expect_name("enum name")?;
        self.skip_newlines();
        self.expect(TokenType::Indent, "")?;
        let mut variants: Vec<(String, Vec<String>)> = Vec::new();

        self.skip_newlines();
        while !self.check_any(&[TokenType::Dedent, TokenType::Eof]) {
            let variant_name = self.expect_name("variant name")?.as_str().to_string();
            let mut fields = Vec::new();
            if self.match_tok(TokenType::LParen).is_some() {
                if !self.check(TokenType::RParen) {
                    fields.push(self.expect_name("payload field name")?.as_str().to_string());
                    while self.match_tok(TokenType::Comma).is_some() {
                        fields.push(self.expect_name("payload field name")?.as_str().to_string());
                    }
                }
                self.expect(TokenType::RParen, "")?;
            }
            variants.push((variant_name, fields));
            self.skip_newlines();
        }

        if self.check(TokenType::Dedent) {
            self.advance();
        }

        Ok(Node::new(
            loc,
            NodeKind::EnumDefinition {
                name: name_tok.as_str().to_string(),
                variants,
            },
        ))
    }

    // -- try/recover --

    fn parse_try_recover(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'try'
        let try_body = self.parse_block()?;

        self.skip_newlines();
        self.expect(TokenType::Recover, "Expected 'recover' after try block")?;

        let mut error_var = "error".to_string();
        if self.check(TokenType::Identifier) {
            error_var = self.advance().as_str().to_string();
        }

        let recover_body = self.parse_block()?;

        Ok(Node::new(
            loc,
            NodeKind::TryRecover {
                try_body,
                error_variable: error_var,
                recover_body,
            },
        ))
    }

    // -- agent --

    fn parse_agent(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let name_tok = self.expect(TokenType::Identifier, "")?;
        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::AgentDefinition {
                name: name_tok.as_str().to_string(),
                initial_state: None,
                capabilities: Vec::new(),
                body,
            },
        ))
    }

    fn parse_spawn(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let name_tok = self.expect(TokenType::Identifier, "")?;
        let mut args: Vec<(String, Node)> = Vec::new();
        if self.match_tok(TokenType::With).is_some() {
            let key = self.expect(TokenType::Identifier, "")?.as_str().to_string();
            self.expect(TokenType::Assign, "")?;
            let value = self.parse_expression()?;
            args.push((key, value));
            while self.match_tok(TokenType::Comma).is_some() {
                let key = self.expect(TokenType::Identifier, "")?.as_str().to_string();
                self.expect(TokenType::Assign, "")?;
                let value = self.parse_expression()?;
                args.push((key, value));
            }
        }
        Ok(Node::new(
            loc,
            NodeKind::SpawnStatement {
                agent_name: name_tok.as_str().to_string(),
                arguments: args,
            },
        ))
    }

    fn parse_share(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let value = self.parse_expression()?;
        self.expect(TokenType::As, "")?;
        let key_expr = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::ShareStatement {
                value: Box::new(value),
                key: Box::new(key_expr),
            },
        ))
    }

    fn parse_observe(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let key_expr = self.parse_expression()?;
        self.expect(TokenType::As, "")?;
        let var_tok = self.expect(TokenType::Identifier, "")?;
        Ok(Node::new(
            loc,
            NodeKind::ObserveStatement {
                key: Box::new(key_expr),
                variable: var_tok.as_str().to_string(),
            },
        ))
    }

    fn parse_signal(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        // El nombre del canal es una EXPRESIÓN (Batch 6): `parse_expression` se detiene en
        // el keyword `with` (TokenType::With), así que la cláusula opcional sigue OK.
        let name = Box::new(self.parse_expression()?);
        let mut data = None;
        if self.match_tok(TokenType::With).is_some() {
            data = Some(Box::new(self.parse_expression()?));
        }
        Ok(Node::new(loc, NodeKind::SignalStatement { name, data }))
    }

    fn parse_wait_for(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        // Nombre como EXPRESIÓN (Batch 6); `parse_expression` se detiene en `as`/`timeout`.
        let signal_name = Box::new(self.parse_expression()?);
        // `timeout <expr>` opcional (Batch 7): SOFT keyword, sólo especial acá, justo entre
        // el nombre y el `as`. La expresión del timeout se detiene en `as` (TokenType::As).
        let mut timeout = None;
        if self.check_word("timeout") {
            self.advance();
            timeout = Some(Box::new(self.parse_expression()?));
        }
        let mut variable = None;
        if self.match_tok(TokenType::As).is_some() {
            variable = Some(self.expect(TokenType::Identifier, "")?.as_str().to_string());
        }
        Ok(Node::new(
            loc,
            NodeKind::WaitForStatement { signal_name, variable, timeout },
        ))
    }

    // -- capabilities --

    fn parse_require(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let cap_tok = self.expect(TokenType::Identifier, "")?;
        let mut scope = None;
        if self.match_tok(TokenType::LParen).is_some() {
            scope = Some(Box::new(self.parse_expression()?));
            self.expect(TokenType::RParen, "")?;
        }
        Ok(Node::new(
            loc,
            NodeKind::RequireStatement {
                capability: cap_tok.as_str().to_string(),
                scope,
            },
        ))
    }

    fn parse_sandbox(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // consume 'sandbox'
        // Forma de bloque:  sandbox\n    body...
        // Forma inline:     sandbox <expr>  (como expresión o en la misma línea)
        let body = if self.check(TokenType::Newline) && self.peek(1).ty == TokenType::Indent {
            self.parse_block()?
        } else {
            vec![self.parse_expression()?]
        };
        Ok(Node::new(
            loc,
            NodeKind::SandboxBlock {
                body,
                allowed_capabilities: Vec::new(),
            },
        ))
    }

    fn parse_invariant(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        self.expect(TokenType::Colon, "")?;
        let condition = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::InvariantDeclaration {
                condition: Box::new(condition),
                description: None,
            },
        ))
    }

    fn parse_intent(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        self.expect(TokenType::Colon, "")?;
        let desc_tok = self.expect(TokenType::Text, "")?;
        Ok(Node::new(
            loc,
            NodeKind::IntentDeclaration {
                description: desc_tok.as_str().to_string(),
            },
        ))
    }

    // -- human interaction --

    fn parse_approve(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let message = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::ApproveStatement {
                message: Box::new(message),
                context: None,
            },
        ))
    }

    fn parse_show(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let value = self.parse_expression()?;
        let mut label = None;
        if self.match_tok(TokenType::As).is_some() {
            label = Some(self.expect(TokenType::Text, "")?.as_str().to_string());
        }
        Ok(Node::new(
            loc,
            NodeKind::ShowStatement {
                value: Box::new(value),
                label,
            },
        ))
    }

    fn parse_confirm(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let message = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::ConfirmStatement {
                message: Box::new(message),
            },
        ))
    }

    // -- observability --

    fn parse_trace(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let name_tok = self.expect(TokenType::Text, "")?;
        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::TraceBlock {
                name: name_tok.as_str().to_string(),
                body,
            },
        ))
    }

    /// `test "<nombre>"` + bloque indentado (Batch 3). El dispatcher ya verificó que tras
    /// `test` viene un Text, así que acá `test` es la palabra del DSL, no un identificador.
    fn parse_test_block(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // soft keyword 'test'
        let name_tok = self.expect(TokenType::Text, "Expected a test name string after 'test'")?;
        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::TestBlock {
                name: name_tok.as_str().to_string(),
                body,
            },
        ))
    }

    fn parse_log(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let message = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::LogStatement {
                message: Box::new(message),
                level: "info".to_string(),
            },
        ))
    }

    fn parse_measure(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let name_tok = self.expect(TokenType::Text, "")?;
        let body = self.parse_block()?;
        Ok(Node::new(
            loc,
            NodeKind::MeasureBlock {
                name: name_tok.as_str().to_string(),
                body,
            },
        ))
    }

    fn parse_checkpoint(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let name = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::CheckpointStatement {
                name: Box::new(name),
            },
        ))
    }

    // -- HTTP server --

    fn parse_serve(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'serve'
        self.expect_word("on", "Expected 'on' after 'serve' (serve on PORT)")?;
        let port = self.parse_expression()?;

        let mut auth_handler = None;
        let mut max_body = None;
        let mut max_streams = None;
        let mut rate_limit: Option<Box<Node>> = None;
        let mut static_mounts = Vec::new();
        let mut cors = None;
        let mut describe = None;
        let mut private = false;
        let mut routes = Vec::new();
        let mut tls_cert: Option<Box<Node>> = None;
        let mut tls_key: Option<Box<Node>> = None;
        let mut redirect_https = false;
        let mut tls_auto = false;
        let mut tls_auto_email: Option<Box<Node>> = None;
        let mut domain: Option<Box<Node>> = None;
        let mut hosts: Vec<Node> = Vec::new();

        self.skip_newlines();
        self.expect(TokenType::Indent, "Expected an indented block after 'serve on PORT'")?;
        self.skip_newlines();

        while !self.at_end() && !self.check(TokenType::Dedent) {
            if self.check_word("auth") {
                self.advance();
                self.expect(TokenType::With, "Expected 'with' after 'auth' (auth with <task>)")?;
                auth_handler = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("max_body") {
                self.advance();
                max_body = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("max_streams") {
                self.advance();
                max_streams = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("rate_limit") {
                rate_limit = Some(Box::new(self.parse_rate_limit()?));
            } else if self.check_word("static") {
                self.advance();
                let first = self.parse_expression()?;
                if self.check_word("from") {
                    self.advance();
                    let directory = self.parse_expression()?;
                    static_mounts.push(Node::new(
                        loc.clone(),
                        NodeKind::StaticMount {
                            directory: Box::new(directory),
                            prefix: Some(Box::new(first)),
                        },
                    ));
                } else {
                    static_mounts.push(Node::new(
                        loc.clone(),
                        NodeKind::StaticMount {
                            directory: Box::new(first),
                            prefix: None,
                        },
                    ));
                }
            } else if self.check_word("cors") {
                self.advance();
                cors = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("describe") {
                describe = Some(Box::new(self.parse_describe()?));
            } else if self.check_word("private") {
                self.advance();
                private = true;
            } else if self.check_word("tls") {
                self.advance();
                if self.check_word("auto") {
                    // tls auto [<email>]  → ACME/auto-HTTPS (Let's Encrypt)
                    self.advance();
                    tls_auto = true;
                    // Email opcional para la cuenta ACME (en la misma línea).
                    if !self.check_any(&[TokenType::Newline, TokenType::Dedent, TokenType::Eof]) {
                        tls_auto_email = Some(Box::new(self.parse_expression()?));
                    }
                } else {
                    // tls cert <expr> key <expr>  → TLS manual
                    self.expect_word("cert", "Expected 'cert' or 'auto' after 'tls' (tls cert <path> key <path> | tls auto [<email>])")?;
                    tls_cert = Some(Box::new(self.parse_expression()?));
                    self.expect_word("key", "Expected 'key' after 'tls cert <path>'")?;
                    tls_key = Some(Box::new(self.parse_expression()?));
                }
            } else if self.check_word("domain") {
                // domain <expr>  → dominio para el cert ACME (auto-HTTPS)
                self.advance();
                domain = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("host") {
                // host "dominio"  + bloque indentado → vhost (Lote 1)
                hosts.push(self.parse_host_block()?);
            } else if self.check_word("redirect") {
                // redirect https
                self.advance();
                self.expect_word("https", "Expected 'https' after 'redirect' (redirect https)")?;
                redirect_https = true;
            } else if self.check_word("route") {
                routes.push(self.parse_route()?);
            } else {
                let tok = self.current();
                return Err(ParseError::new(
                    format!(
                        "Inside 'serve', expected 'auth with ...', 'route ...', 'static ...', 'tls ...', 'domain ...', 'host \"...\"', 'redirect https', 'cors ...', 'describe' or 'private', got {}",
                        tok.ty.name()
                    ),
                    tok.location.clone(),
                ));
            }
            self.skip_newlines();
        }

        if self.check(TokenType::Dedent) {
            self.advance();
        }

        // Una route con 'requires auth' exige 'auth with <task>' en el bloque.
        if auth_handler.is_none() {
            for r in &routes {
                if let NodeKind::RouteDefinition {
                    requires_auth,
                    method,
                    path,
                    ..
                } = &r.kind
                {
                    if *requires_auth {
                        return Err(ParseError::new(
                            format!(
                                "route \"{} {}\" uses 'requires auth' but the 'serve' block declares no 'auth with <task>'",
                                method, path
                            ),
                            r.location.clone(),
                        ));
                    }
                }
            }
        }

        Ok(Node::new(
            loc,
            NodeKind::ServeBlock {
                port: Box::new(port),
                auth_handler,
                max_body,
                max_streams,
                rate_limit,
                static_mounts,
                cors,
                describe,
                private,
                routes,
                tls_cert,
                tls_key,
                redirect_https,
                tls_auto,
                tls_auto_email,
                domain,
                hosts,
            },
        ))
    }

    /// vhost: `host "dominio"` seguido de un bloque indentado con su propia
    /// tabla (auth/static/tls/route). Espeja la forma de `serve` pero por-host.
    fn parse_host_block(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'host'
        let pattern = self.parse_expression()?;
        let mut auth_handler: Option<Box<Node>> = None;
        let mut static_mounts: Vec<Node> = Vec::new();
        let mut routes: Vec<Node> = Vec::new();
        let mut tls_cert: Option<Box<Node>> = None;
        let mut tls_key: Option<Box<Node>> = None;

        self.skip_newlines();
        self.expect(TokenType::Indent, "Expected an indented block after 'host \"...\"'")?;
        self.skip_newlines();

        while !self.at_end() && !self.check(TokenType::Dedent) {
            if self.check_word("auth") {
                self.advance();
                self.expect(TokenType::With, "Expected 'with' after 'auth' (auth with <task>)")?;
                auth_handler = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("static") {
                self.advance();
                let first = self.parse_expression()?;
                if self.check_word("from") {
                    self.advance();
                    let directory = self.parse_expression()?;
                    static_mounts.push(Node::new(
                        loc.clone(),
                        NodeKind::StaticMount {
                            directory: Box::new(directory),
                            prefix: Some(Box::new(first)),
                        },
                    ));
                } else {
                    static_mounts.push(Node::new(
                        loc.clone(),
                        NodeKind::StaticMount { directory: Box::new(first), prefix: None },
                    ));
                }
            } else if self.check_word("tls") {
                // tls cert <expr> key <expr>  (cert por-host para SNI)
                self.advance();
                self.expect_word("cert", "Expected 'cert' after 'tls' in a host block (tls cert <path> key <path>)")?;
                tls_cert = Some(Box::new(self.parse_expression()?));
                self.expect_word("key", "Expected 'key' after 'tls cert <path>'")?;
                tls_key = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("route") {
                routes.push(self.parse_route()?);
            } else {
                let tok = self.current();
                return Err(ParseError::new(
                    format!(
                        "Inside a 'host' block, expected 'auth with ...', 'route ...', 'static ...' or 'tls cert ... key ...', got {}",
                        tok.ty.name()
                    ),
                    tok.location.clone(),
                ));
            }
            self.skip_newlines();
        }

        if self.check(TokenType::Dedent) {
            self.advance();
        }

        Ok(Node::new(
            loc,
            NodeKind::HostBlock {
                pattern: Box::new(pattern),
                auth_handler,
                static_mounts,
                routes,
                tls_cert,
                tls_key,
            },
        ))
    }

    fn parse_describe(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'describe'
        let mut about = None;
        let mut api = None;
        self.skip_newlines();
        self.expect(TokenType::Indent, "Expected an indented block after 'describe'")?;
        self.skip_newlines();
        while !self.at_end() && !self.check(TokenType::Dedent) {
            if self.check_word("about") {
                self.advance();
                self.expect(TokenType::Colon, "Expected ':' after 'about'")?;
                about = Some(Box::new(self.parse_expression()?));
            } else if self.check_word("api") {
                self.advance();
                self.expect(TokenType::Colon, "Expected ':' after 'api'")?;
                api = Some(Box::new(self.parse_expression()?));
            } else {
                let tok = self.current();
                return Err(ParseError::new(
                    format!(
                        "Inside 'describe', expected 'about:' or 'api:', got {}",
                        tok.ty.name()
                    ),
                    tok.location.clone(),
                ));
            }
            self.skip_newlines();
        }
        if self.check(TokenType::Dedent) {
            self.advance();
        }
        Ok(Node::new(loc, NodeKind::DescribeClause { about, api }))
    }

    fn parse_route(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'route'
        let spec_tok = self.expect(TokenType::Text, "Expected a route spec string, e.g. \"GET /path\"")?;
        let (method, path, param_names) =
            self.split_route_spec(spec_tok.as_str(), &spec_tok.location)?;

        let mut requires_auth = false;
        if self.check_word("requires") {
            self.advance();
            self.expect_word("auth", "Expected 'auth' after 'requires' (requires auth)")?;
            requires_auth = true;
        }

        let body = self.parse_block()?;
        // Un rate_limit dentro del body de la route es un override de ruta.
        let mut rate_limit = None;
        let mut clean_body = Vec::new();
        for s in body {
            if matches!(s.kind, NodeKind::RateLimitClause { .. }) {
                rate_limit = Some(Box::new(s));
            } else {
                clean_body.push(s);
            }
        }
        let streaming = clean_body
            .iter()
            .any(|s| matches!(s.kind, NodeKind::StreamBlock { .. }));
        Ok(Node::new(
            loc,
            NodeKind::RouteDefinition {
                method,
                path,
                param_names,
                requires_auth,
                streaming,
                rate_limit,
                body: clean_body,
            },
        ))
    }

    /// `proxy to <url-expr>` (Lote 2): forward de la request al upstream.
    fn parse_proxy(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'proxy'
        self.expect(TokenType::To, "Expected 'to' after 'proxy' (proxy to \"http://upstream\")")?;
        let target = self.parse_expression()?;
        Ok(Node::new(loc, NodeKind::ProxyStatement { target: Box::new(target) }))
    }

    fn parse_rate_limit(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'rate_limit'
        if self.check_word("none") || self.check_word("unlimited") {
            self.advance();
            return Ok(Node::new(
                loc,
                NodeKind::RateLimitClause {
                    count: None,
                    window: "minute".to_string(),
                    unlimited: true,
                },
            ));
        }
        let count = self.parse_expression()?;
        self.expect_word("per", "Expected 'per' in rate_limit (e.g. rate_limit 100 per minute)")?;
        let window_tok = self.expect(TokenType::Identifier, "Expected a window: second, minute, or hour")?;
        let window = window_tok.as_str().to_string();
        if !matches!(window.as_str(), "second" | "minute" | "hour") {
            return Err(ParseError::new(
                format!(
                    "rate_limit window must be second, minute, or hour, got {}",
                    py_repr_str(&window)
                ),
                window_tok.location.clone(),
            ));
        }
        Ok(Node::new(
            loc,
            NodeKind::RateLimitClause {
                count: Some(Box::new(count)),
                window,
                unlimited: false,
            },
        ))
    }

    fn parse_stream(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'stream'
        self.stream_depth += 1;
        let body_result = self.parse_block();
        self.stream_depth -= 1;
        let body = body_result?;
        Ok(Node::new(loc, NodeKind::StreamBlock { body }))
    }

    fn parse_send(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'send'
        let value = self.parse_expression()?;
        let mut event_name = None;
        if self.match_tok(TokenType::As).is_some() {
            let ev_tok = self.expect(TokenType::Text, "Expected an event name string after 'as'")?;
            event_name = Some(ev_tok.as_str().to_string());
        }
        Ok(Node::new(
            loc,
            NodeKind::SendStatement {
                value: Box::new(value),
                event_name,
            },
        ))
    }

    /// 'GET /products/:id' → ('GET', '/products/:id', ['id']). Soporta un único
    /// segmento catch-all final '*path'.
    fn split_route_spec(
        &self,
        spec: &str,
        loc: &SourceLocation,
    ) -> Result<(String, String, Vec<String>), ParseError> {
        let stripped = spec.trim();
        let parts: Vec<&str> = stripped.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() != 2 {
            return Err(ParseError::new(
                format!("Route spec must be \"METHOD /path\", got {}", py_repr_str(spec)),
                loc.clone(),
            ));
        }
        let method = parts[0].to_uppercase();
        let path = parts[1].trim().to_string();
        if !path.starts_with('/') {
            return Err(ParseError::new(
                format!("Route path must start with '/', got {}", py_repr_str(&path)),
                loc.clone(),
            ));
        }
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut param_names = Vec::new();
        let n = segs.len();
        for (i, seg) in segs.iter().enumerate() {
            if seg.starts_with(':') && seg.len() > 1 {
                param_names.push(seg[1..].to_string());
            } else if seg.starts_with('*') {
                if seg.len() == 1 {
                    return Err(ParseError::new(
                        format!("Catch-all segment must be named, e.g. '*path', got {}", py_repr_str(seg)),
                        loc.clone(),
                    ));
                }
                if i != n - 1 {
                    return Err(ParseError::new(
                        format!(
                            "Catch-all '*{}' must be the LAST segment of the path, got {}",
                            &seg[1..],
                            py_repr_str(&path)
                        ),
                        loc.clone(),
                    ));
                }
                param_names.push(seg[1..].to_string());
            }
        }
        Ok((method, path, param_names))
    }

    fn parse_expect(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'expect'
        let target_tok = self.expect_word("body", "Expected 'body' after 'expect'")?;
        self.expect(TokenType::LBrace, "Expected '{' to declare the expected shape")?;
        let mut shape = Vec::new();
        if !self.check(TokenType::RBrace) {
            shape.push(self.parse_expect_field()?);
            while self.match_tok(TokenType::Comma).is_some() {
                if self.check(TokenType::RBrace) {
                    break;
                }
                shape.push(self.parse_expect_field()?);
            }
        }
        self.expect(TokenType::RBrace, "Expected '}' to close the expected shape")?;
        Ok(Node::new(
            loc,
            NodeKind::ExpectStatement {
                target: target_tok.as_str().to_string(),
                shape,
            },
        ))
    }

    fn parse_expect_field(&mut self) -> Result<(String, String), ParseError> {
        let field_tok = self.expect(TokenType::Identifier, "Expected a field name in expect shape")?;
        self.expect(TokenType::Colon, "Expected ':' after field name in expect shape")?;
        let type_tok = self.expect(
            TokenType::Identifier,
            "Expected a type name (text, number, bool, list, map)",
        )?;
        Ok((field_tok.as_str().to_string(), type_tok.as_str().to_string()))
    }

    // =========================================================
    // Expressions (Pratt / precedence climbing)
    // =========================================================

    fn parse_expression(&mut self) -> Result<Node, ParseError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_and()?;
        while self.check(TokenType::Or) {
            let op = self.advance();
            let right = self.parse_and()?;
            left = Node::new(
                op.location,
                NodeKind::BinaryOp {
                    left: Box::new(left),
                    operator: "or".to_string(),
                    right: Box::new(right),
                },
            );
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_not()?;
        while self.check(TokenType::And) {
            let op = self.advance();
            let right = self.parse_not()?;
            left = Node::new(
                op.location,
                NodeKind::BinaryOp {
                    left: Box::new(left),
                    operator: "and".to_string(),
                    right: Box::new(right),
                },
            );
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Node, ParseError> {
        if self.check(TokenType::Not) {
            let op = self.advance();
            let operand = self.parse_not()?;
            return Ok(Node::new(
                op.location,
                NodeKind::UnaryOp {
                    operator: "not".to_string(),
                    operand: Box::new(operand),
                },
            ));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_addition()?;
        while self.check_any(&[
            TokenType::Equal,
            TokenType::NotEqual,
            TokenType::Less,
            TokenType::Greater,
            TokenType::LessEqual,
            TokenType::GreaterEqual,
        ]) {
            let op = self.advance();
            let right = self.parse_addition()?;
            left = Node::new(
                op.location.clone(),
                NodeKind::BinaryOp {
                    left: Box::new(left),
                    operator: op.as_str().to_string(),
                    right: Box::new(right),
                },
            );
        }
        Ok(left)
    }

    fn parse_addition(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_multiplication()?;
        while self.check_any(&[TokenType::Plus, TokenType::Minus]) {
            let op = self.advance();
            let right = self.parse_multiplication()?;
            left = Node::new(
                op.location.clone(),
                NodeKind::BinaryOp {
                    left: Box::new(left),
                    operator: op.as_str().to_string(),
                    right: Box::new(right),
                },
            );
        }
        Ok(left)
    }

    fn parse_multiplication(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_power()?;
        while self.check_any(&[TokenType::Star, TokenType::Slash, TokenType::Percent]) {
            let op = self.advance();
            let right = self.parse_power()?;
            left = Node::new(
                op.location.clone(),
                NodeKind::BinaryOp {
                    left: Box::new(left),
                    operator: op.as_str().to_string(),
                    right: Box::new(right),
                },
            );
        }
        Ok(left)
    }

    fn parse_power(&mut self) -> Result<Node, ParseError> {
        let left = self.parse_unary()?;
        if self.check(TokenType::Power) {
            let op = self.advance();
            let right = self.parse_power()?; // asociativo a derecha
            return Ok(Node::new(
                op.location,
                NodeKind::BinaryOp {
                    left: Box::new(left),
                    operator: "**".to_string(),
                    right: Box::new(right),
                },
            ));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Node, ParseError> {
        if self.check(TokenType::Minus) {
            let op = self.advance();
            let operand = self.parse_unary()?;
            return Ok(Node::new(
                op.location,
                NodeKind::UnaryOp {
                    operator: "-".to_string(),
                    operand: Box::new(operand),
                },
            ));
        }
        self.parse_pipe()
    }

    fn parse_pipe(&mut self) -> Result<Node, ParseError> {
        let left = self.parse_postfix()?;
        if self.check(TokenType::Pipe) {
            let loc = self.location();
            let mut transforms = Vec::new();
            while self.match_tok(TokenType::Pipe).is_some() {
                transforms.push(self.parse_postfix()?);
            }
            return Ok(Node::new(
                loc,
                NodeKind::PipeExpression {
                    value: Box::new(left),
                    transforms,
                },
            ));
        }
        Ok(left)
    }

    fn parse_postfix(&mut self) -> Result<Node, ParseError> {
        let mut node = self.parse_primary()?;

        loop {
            if self.check(TokenType::LParen) {
                let loc = self.location();
                self.advance();
                let mut args = Vec::new();
                if !self.check(TokenType::RParen) {
                    args.push(self.parse_arg()?);
                    while self.match_tok(TokenType::Comma).is_some() {
                        args.push(self.parse_arg()?);
                    }
                }
                self.expect(TokenType::RParen, "")?;
                node = Node::new(
                    loc,
                    NodeKind::TaskCall {
                        name: Box::new(node),
                        arguments: args,
                    },
                );
            } else if self.check(TokenType::Dot) {
                let loc = self.location();
                self.advance();
                let prop = self.expect(TokenType::Identifier, "")?;
                node = Node::new(
                    loc,
                    NodeKind::PropertyAccess {
                        property_name: prop.as_str().to_string(),
                        object: Box::new(node),
                    },
                );
            } else if self.check(TokenType::LBracket) {
                let loc = self.location();
                self.advance();
                let index = self.parse_expression()?;
                self.expect(TokenType::RBracket, "")?;
                node = Node::new(
                    loc,
                    NodeKind::IndexAccess {
                        object: Box::new(node),
                        index: Box::new(index),
                    },
                );
            } else if self.check(TokenType::Of) {
                // "name of person" → PropertyAccess
                let loc = self.location();
                self.advance();
                let obj = self.parse_postfix()?;
                let property_name = match &node.kind {
                    NodeKind::Identifier { name } => name.clone(),
                    // Camino casi inexistente (X no-identificador). str(node) en Python.
                    _ => format!("{:?}", node.kind),
                };
                node = Node::new(
                    loc,
                    NodeKind::PropertyAccess {
                        property_name,
                        object: Box::new(obj),
                    },
                );
            } else {
                break;
            }
        }

        Ok(node)
    }

    /// Un argumento de llamada: posicional (`expr`) o nombrado (`name = expr`, Batch 2).
    /// El nombrado se distingue por el token `Assign` (`=`) tras un identificador; `name ==
    /// expr` usa `Equal` y es un arg posicional booleano (no se confunden).
    fn parse_arg(&mut self) -> Result<Arg, ParseError> {
        if self.check(TokenType::Identifier) && self.peek(1).ty == TokenType::Assign {
            let name = self.advance().as_str().to_string();
            self.advance(); // '='
            let value = self.parse_expression()?;
            return Ok(Arg { name: Some(name), value });
        }
        let value = self.parse_expression()?;
        Ok(Arg { name: None, value })
    }

    /// En un '(', indica si su ')' de cierre va seguido inmediatamente de '=>'.
    /// Lookahead acotado que no consume nada: sólo cuenta profundidad de
    /// paréntesis, así la desambiguación funciona sin importar qué haya dentro.
    /// Un '(' cuyo cierre va seguido de '=>' abre una lista de parámetros de
    /// lambda; cualquier otra cosa (p.ej. `(1 + 2) * 3`) es una agrupación.
    fn is_lambda_ahead(&self) -> bool {
        let mut depth: i32 = 0;
        let mut i = self.pos;
        let n = self.tokens.len();
        while i < n {
            match self.tokens[i].ty {
                TokenType::LParen => depth += 1,
                TokenType::RParen => {
                    depth -= 1;
                    if depth == 0 {
                        let nxt = i + 1;
                        return nxt < n && self.tokens[nxt].ty == TokenType::FatArrow;
                    }
                }
                TokenType::Eof => break,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// `(params) => expr` — función anónima de una sola expresión.
    /// Params: cero o más identificadores (paréntesis siempre), igual que la
    /// lista de params de un task. El cuerpo es una única expresión completa.
    fn parse_lambda(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.expect(TokenType::LParen, "")?;
        let mut params = Vec::new();
        if !self.check(TokenType::RParen) {
            params.push(self.expect_name("lambda parameter")?.as_str().to_string());
            while self.match_tok(TokenType::Comma).is_some() {
                params.push(self.expect_name("lambda parameter")?.as_str().to_string());
            }
        }
        self.expect(TokenType::RParen, "")?;
        self.expect(TokenType::FatArrow, "")?;
        let body = self.parse_expression()?;
        Ok(Node::new(
            loc,
            NodeKind::LambdaExpression {
                parameters: params,
                body: Box::new(body),
            },
        ))
    }

    /// Desugara un template (backtick) a una cadena `+` asociada a izquierda (§5).
    /// literal → TextLiteral; interp → su expresión parseada. El primer operando
    /// se fuerza a TextLiteral (usa "") para que todo el template evalúe a texto
    /// vía el `+` que coacciona. Template puro-literal → un solo TextLiteral;
    /// vacío → "". AST e intérprete intactos (solo TextLiteral + BinaryOp).
    fn desugar_template(
        &self,
        segments: Vec<TemplateSegment>,
        loc: &SourceLocation,
    ) -> Result<Node, ParseError> {
        let mut node: Option<Node> = None;
        for seg in segments {
            let part = match seg {
                TemplateSegment::Literal(text) => {
                    Node::new(loc.clone(), NodeKind::TextLiteral { value: text })
                }
                TemplateSegment::Interp(src, _interp_loc) => {
                    self.parse_interp_expression(&src, loc)?
                }
            };
            node = Some(match node {
                None if matches!(part.kind, NodeKind::TextLiteral { .. }) => part,
                None => Node::new(
                    loc.clone(),
                    NodeKind::BinaryOp {
                        left: Box::new(Node::new(
                            loc.clone(),
                            NodeKind::TextLiteral { value: String::new() },
                        )),
                        operator: "+".to_string(),
                        right: Box::new(part),
                    },
                ),
                Some(acc) => Node::new(
                    loc.clone(),
                    NodeKind::BinaryOp {
                        left: Box::new(acc),
                        operator: "+".to_string(),
                        right: Box::new(part),
                    },
                ),
            });
        }
        Ok(node.unwrap_or_else(|| {
            Node::new(loc.clone(), NodeKind::TextLiteral { value: String::new() })
        }))
    }

    /// Parsea el source de un hole `{ … }` como una sola expresión. Espeja el
    /// oráculo: trimea (convención de los holes SSR) y reusa
    /// `parse_expression_source` (lex + UNA expresión, sin chequeo de tokens
    /// sobrantes). Un error de lexer se convierte a ParseError para que ambas
    /// implementaciones reporten la misma categoría en el gate de paridad.
    fn parse_interp_expression(
        &self,
        src: &str,
        loc: &SourceLocation,
    ) -> Result<Node, ParseError> {
        match parse_expression_source(src.trim(), &loc.file) {
            Ok(node) => Ok(node),
            Err(CompileError::Parse(e)) => Err(e),
            Err(CompileError::Lex(e)) => Err(ParseError::new(e.message, e.location)),
        }
    }

    fn parse_primary(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        let tok = self.current().clone();

        // Soft DSL keywords en posición de primary (ask/show/approve/confirm):
        // son la construcción del DSL sólo si no las sigue `(`/`.`/`[`/operador/`of`;
        // si no, caen al arm Identifier de abajo (uso como nombre). §3.
        if self.soft_dsl("ask") {
            return self.parse_ask_expr();
        }
        if self.soft_dsl("approve") {
            return self.parse_approve();
        }
        if self.soft_dsl("confirm") {
            return self.parse_confirm();
        }
        if self.soft_dsl("show") {
            return self.parse_show();
        }

        match tok.ty {
            TokenType::Number => {
                self.advance();
                Ok(Node::new(loc, NodeKind::NumberLiteral { value: tok.as_number() }))
            }
            TokenType::Text => {
                self.advance();
                Ok(Node::new(loc, NodeKind::TextLiteral { value: tok.as_str().to_string() }))
            }
            TokenType::Template => {
                self.advance();
                let segments = match tok.value {
                    TokenValue::Template(segs) => segs,
                    _ => Vec::new(),
                };
                self.desugar_template(segments, &loc)
            }
            TokenType::BoolTrue => {
                self.advance();
                Ok(Node::new(loc, NodeKind::BoolLiteral { value: true }))
            }
            TokenType::BoolFalse => {
                self.advance();
                Ok(Node::new(loc, NodeKind::BoolLiteral { value: false }))
            }
            TokenType::Nothing => {
                self.advance();
                Ok(Node::new(loc, NodeKind::NothingLiteral))
            }
            TokenType::Identifier => {
                self.advance();
                Ok(Node::new(loc, NodeKind::Identifier { name: tok.as_str().to_string() }))
            }
            TokenType::LBracket => {
                self.advance();
                let mut elements = Vec::new();
                if !self.check(TokenType::RBracket) {
                    elements.push(self.parse_expression()?);
                    while self.match_tok(TokenType::Comma).is_some() {
                        if self.check(TokenType::RBracket) {
                            break; // coma final
                        }
                        elements.push(self.parse_expression()?);
                    }
                }
                self.expect(TokenType::RBracket, "")?;
                Ok(Node::new(loc, NodeKind::ListLiteral { elements }))
            }
            TokenType::LBrace => {
                self.advance();
                let mut pairs = Vec::new();
                if !self.check(TokenType::RBrace) {
                    let key = self.parse_expression()?;
                    self.expect(TokenType::Colon, "")?;
                    let val = self.parse_expression()?;
                    pairs.push((key, val));
                    while self.match_tok(TokenType::Comma).is_some() {
                        if self.check(TokenType::RBrace) {
                            break;
                        }
                        let key = self.parse_expression()?;
                        self.expect(TokenType::Colon, "")?;
                        let val = self.parse_expression()?;
                        pairs.push((key, val));
                    }
                }
                self.expect(TokenType::RBrace, "")?;
                Ok(Node::new(loc, NodeKind::MapLiteral { pairs }))
            }
            TokenType::LParen => {
                // Lambda `(params) => expr` o expresión agrupada `(expr)`.
                if self.is_lambda_ahead() {
                    self.parse_lambda()
                } else {
                    self.advance();
                    let expr = self.parse_expression()?;
                    self.expect(TokenType::RParen, "")?;
                    Ok(expr)
                }
            }
            TokenType::Reason => self.parse_reason_expr(),
            TokenType::Decide => self.parse_decide_expr(),
            TokenType::Analyze => self.parse_analyze_expr(),
            TokenType::Generate => self.parse_generate_expr(),
            TokenType::Sandbox => self.parse_sandbox(),
            TokenType::When => self.parse_when(),
            _ => Err(ParseError::new(
                format!(
                    "Unexpected token: {} ({})",
                    tok.ty.name(),
                    token_value_repr(&tok.value)
                ),
                loc,
            )),
        }
    }

    // -- LLM expression parsers --

    fn parse_reason_expr(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'reason'
        let mut subject = None;
        if self.current_value_eq("about") {
            self.advance();
            subject = Some(Box::new(self.parse_expression()?));
        }
        let mut context: Vec<(String, Node)> = Vec::new();
        if self.match_tok(TokenType::With).is_some() {
            let key = self.expect(TokenType::Identifier, "")?.as_str().to_string();
            self.expect(TokenType::Assign, "")?;
            let val = self.parse_expression()?;
            context.push((key, val));
        }
        let mut body = Vec::new();
        if self.check(TokenType::Newline) && self.peek(1).ty == TokenType::Indent {
            body = self.parse_block()?;
        }
        Ok(Node::new(loc, NodeKind::ReasonExpression { subject, context, body }))
    }

    fn parse_decide_expr(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance(); // 'decide'
        let mut options = None;
        if self.current_value_eq("between") {
            self.advance();
            options = Some(Box::new(self.parse_expression()?));
        }
        let mut given = None;
        if self.current_value_eq("given") {
            self.advance();
            given = Some(Box::new(self.parse_expression()?));
        }
        Ok(Node::new(
            loc,
            NodeKind::DecideExpression {
                options,
                given,
                criteria: None,
            },
        ))
    }

    fn parse_analyze_expr(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let data = self.parse_expression()?;
        let mut objective = String::new();
        if self.current_value_eq("for") {
            self.advance();
            let obj_tok = self.expect(TokenType::Text, "")?;
            objective = obj_tok.as_str().to_string();
        }
        Ok(Node::new(
            loc,
            NodeKind::AnalyzeExpression {
                data: Box::new(data),
                objective,
            },
        ))
    }

    fn parse_generate_expr(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let target_tok = self.expect(TokenType::Text, "")?;
        let mut given = None;
        if self.current_value_eq("given") {
            self.advance();
            given = Some(Box::new(self.parse_expression()?));
        }
        let mut params: Vec<(String, Node)> = Vec::new();
        if self.match_tok(TokenType::With).is_some() {
            let key = self.expect(TokenType::Identifier, "")?.as_str().to_string();
            self.expect(TokenType::Assign, "")?;
            let val = self.parse_expression()?;
            params.push((key, val));
        }
        Ok(Node::new(
            loc,
            NodeKind::GenerateExpression {
                target: target_tok.as_str().to_string(),
                given,
                parameters: params,
            },
        ))
    }

    fn parse_ask_expr(&mut self) -> Result<Node, ParseError> {
        let loc = self.location();
        self.advance();
        let prompt = self.parse_expression()?;
        let mut options = None;
        if self.match_tok(TokenType::With).is_some() {
            options = Some(Box::new(self.parse_expression()?));
        }
        Ok(Node::new(
            loc,
            NodeKind::AskExpression {
                prompt: Box::new(prompt),
                options,
            },
        ))
    }
}

/// Conveniencia: código fuente → AST (lexer + parser).
pub fn parse_source(source: &str, filename: &str) -> Result<Program, CompileError> {
    let tokens = Lexer::new(source, filename).tokenize_filtered()?;
    let mut parser = Parser::new(tokens, filename);
    Ok(parser.parse()?)
}

/// Parsea una sola expresión (para los holes `{ expr }` de templates).
pub fn parse_expression_source(source: &str, filename: &str) -> Result<Node, CompileError> {
    let tokens = Lexer::new(source, filename).tokenize_filtered()?;
    let mut parser = Parser::new(tokens, filename);
    Ok(parser.parse_expression()?)
}

/// Parsea la cláusula `item in collection` de un `{ each ... }` de template →
/// (nombre de variable, expresión de la colección).
pub fn parse_each_clause(source: &str, filename: &str) -> Result<(String, Node), CompileError> {
    let tokens = Lexer::new(source, filename).tokenize_filtered()?;
    let mut p = Parser::new(tokens, filename);
    if p.current().ty != TokenType::Identifier {
        return Err(CompileError::Parse(ParseError::new(
            "expected a loop variable",
            p.current().location.clone(),
        )));
    }
    let var = p.advance().as_str().to_string();
    if p.current().ty != TokenType::In {
        return Err(CompileError::Parse(ParseError::new(
            "expected 'in'",
            p.current().location.clone(),
        )));
    }
    p.advance();
    let coll = p.parse_expression()?;
    Ok((var, coll))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(src: &str) -> Program {
        parse_source(src, "<test>").unwrap_or_else(|e| panic!("parse error: {}", e))
    }

    #[test]
    fn let_and_call() {
        let prog = parse_ok("let x be 5\nprint(x)");
        assert_eq!(prog.statements.len(), 2);
        assert!(matches!(prog.statements[0].kind, NodeKind::LetBinding { .. }));
        assert!(matches!(prog.statements[1].kind, NodeKind::TaskCall { .. }));
    }

    #[test]
    fn parse_proxy_route() {
        // `proxy to "..."` dentro de una route (Lote 2). `to` es TokenType::To, no
        // un identifier — este test cubre el parseo (que un bug previo rompió).
        let prog = parse_ok(
            "require serve(8080)\nserve on 8080\n    route \"GET /up/*path\"\n        proxy to \"http://127.0.0.1:9000\"\n",
        );
        let serve = prog
            .statements
            .iter()
            .find(|s| matches!(s.kind, NodeKind::ServeBlock { .. }))
            .expect("serve block");
        let NodeKind::ServeBlock { routes, .. } = &serve.kind else { unreachable!() };
        assert_eq!(routes.len(), 1);
        let NodeKind::RouteDefinition { body, .. } = &routes[0].kind else {
            panic!("no es RouteDefinition")
        };
        assert_eq!(body.len(), 1, "el body de la route debería ser [ProxyStatement]");
        assert!(
            matches!(body[0].kind, NodeKind::ProxyStatement { .. }),
            "el body de la route no es ProxyStatement"
        );
    }

    #[test]
    fn reserved_word_as_name() {
        let err = parse_source("let task be 1", "<test>").unwrap_err();
        assert!(
            err.to_string().contains("'task' is a reserved word in Synsema"),
            "got: {}",
            err
        );
    }

    #[test]
    fn unary_minus_below_power() {
        // -2 ** 2 parsea como (-2) ** 2 (menos unario debajo de power).
        let prog = parse_ok("let x be -2 ** 2");
        if let NodeKind::LetBinding { value, .. } = &prog.statements[0].kind {
            match &value.kind {
                NodeKind::BinaryOp { left, operator, .. } => {
                    assert_eq!(operator, "**");
                    assert!(matches!(left.kind, NodeKind::UnaryOp { .. }));
                }
                other => panic!("esperaba BinaryOp **, got {:?}", other),
            }
        } else {
            panic!("esperaba LetBinding");
        }
    }

    #[test]
    fn name_of_person() {
        let prog = parse_ok("print(name of person)");
        // print( PropertyAccess(name, person) )
        if let NodeKind::TaskCall { arguments, .. } = &prog.statements[0].kind {
            match &arguments[0].value.kind {
                NodeKind::PropertyAccess { property_name, .. } => {
                    assert_eq!(property_name, "name");
                }
                other => panic!("esperaba PropertyAccess, got {:?}", other),
            }
        } else {
            panic!("esperaba TaskCall");
        }
    }

    #[test]
    fn soft_keyword_serve_as_identifier() {
        // `let serve be 1` es válido: serve es soft keyword.
        let prog = parse_ok("let serve be 1");
        assert!(matches!(prog.statements[0].kind, NodeKind::LetBinding { .. }));
    }

    #[test]
    fn serve_block() {
        let src = "serve on 8080\n    route \"GET /ping\"\n        give \"pong\"\n";
        let prog = parse_ok(src);
        assert!(matches!(prog.statements[0].kind, NodeKind::ServeBlock { .. }));
    }

    #[test]
    fn route_spec_must_start_with_slash() {
        let src = "serve on 80\n    route \"GET ping\"\n        give 1\n";
        let err = parse_source(src, "<test>").unwrap_err();
        assert!(err.to_string().contains("Route path must start with '/'"), "got: {}", err);
    }

    #[test]
    fn requires_auth_without_auth_handler() {
        let src = "serve on 80\n    route \"GET /x\" requires auth\n        give 1\n";
        let err = parse_source(src, "<test>").unwrap_err();
        assert!(
            err.to_string().contains("uses 'requires auth' but the 'serve' block declares no"),
            "got: {}",
            err
        );
    }

    // -- Lambdas: (params) => expr --

    fn lambda_value(src: &str) -> Node {
        let prog = parse_ok(src);
        match &prog.statements[0].kind {
            NodeKind::LetBinding { value, .. } => (**value).clone(),
            other => panic!("esperaba LetBinding, got {:?}", other),
        }
    }

    #[test]
    fn lambda_single_param_parses() {
        let lam = lambda_value("let f be (x) => x + 1");
        match &lam.kind {
            NodeKind::LambdaExpression { parameters, body } => {
                assert_eq!(parameters, &["x"]);
                assert!(matches!(body.kind, NodeKind::BinaryOp { .. }));
            }
            other => panic!("esperaba LambdaExpression, got {:?}", other),
        }
    }

    #[test]
    fn lambda_zero_params_parses() {
        let lam = lambda_value("let f be () => 42");
        match &lam.kind {
            NodeKind::LambdaExpression { parameters, .. } => assert!(parameters.is_empty()),
            other => panic!("esperaba LambdaExpression, got {:?}", other),
        }
    }

    #[test]
    fn lambda_multi_params_parses() {
        let lam = lambda_value("let f be (a, b, c) => a");
        match &lam.kind {
            NodeKind::LambdaExpression { parameters, .. } => {
                assert_eq!(parameters, &["a", "b", "c"]);
            }
            other => panic!("esperaba LambdaExpression, got {:?}", other),
        }
    }

    #[test]
    fn lambda_nested_curried_parses() {
        // (m) => (n) => m * n : el cuerpo es a su vez una lambda.
        let lam = lambda_value("let curry be (m) => (n) => m * n");
        let NodeKind::LambdaExpression { parameters, body } = &lam.kind else {
            panic!("esperaba LambdaExpression externa");
        };
        assert_eq!(parameters, &["m"]);
        assert!(
            matches!(body.kind, NodeKind::LambdaExpression { .. }),
            "el cuerpo de la lambda externa debería ser otra lambda"
        );
    }

    #[test]
    fn grouped_expr_not_lambda_regression() {
        // (1 + 2) * 3 debe seguir siendo una expresión agrupada (BinaryOp *).
        let val = lambda_value("let x be (1 + 2) * 3");
        match &val.kind {
            NodeKind::BinaryOp { operator, .. } => assert_eq!(operator, "*"),
            other => panic!("esperaba BinaryOp *, got {:?}", other),
        }
    }

    #[test]
    fn nested_parens_call_not_lambda_regression() {
        // f((x)) no involucra ninguna lambda: el argumento es x agrupado.
        let prog = parse_ok("let y be identity((x))");
        let NodeKind::LetBinding { value, .. } = &prog.statements[0].kind else {
            panic!("esperaba LetBinding");
        };
        let NodeKind::TaskCall { arguments, .. } = &value.kind else {
            panic!("esperaba TaskCall");
        };
        assert_eq!(arguments[0].value.as_identifier(), Some("x"));
    }

    #[test]
    fn list_and_map_literals_unaffected() {
        // Los literales de lista/map siguen parseando (no hay '(' que confunda).
        let l = lambda_value("let xs be [1, 2, 3]");
        assert!(matches!(l.kind, NodeKind::ListLiteral { .. }));
        let m = lambda_value("let mp be {\"a\": 1}");
        assert!(matches!(m.kind, NodeKind::MapLiteral { .. }));
    }

    #[test]
    fn lambda_non_identifier_param_fails() {
        // (1 + 2) => x : los params deben ser identificadores.
        let err = parse_source("let f be (1 + 2) => x", "<test>").unwrap_err();
        assert!(err.to_string().contains("lambda parameter"), "got: {}", err);
    }

    #[test]
    fn lambda_missing_body_fails() {
        assert!(parse_source("let f be () =>", "<test>").is_err());
    }

    // -- Backtick templates: desugar a cadena `+` --

    #[test]
    fn template_desugars_to_plus_chain() {
        // `a{b}c` -> (("a" + b) + "c")
        let val = lambda_value("let s be `a{b}c`");
        let NodeKind::BinaryOp { left, operator, right } = &val.kind else {
            panic!("esperaba BinaryOp, got {:?}", val.kind);
        };
        assert_eq!(operator, "+");
        assert!(matches!(&right.kind, NodeKind::TextLiteral { value } if value == "c"));
        let NodeKind::BinaryOp { left: l2, operator: op2, right: r2 } = &left.kind else {
            panic!("esperaba BinaryOp interno");
        };
        assert_eq!(op2, "+");
        assert!(matches!(&l2.kind, NodeKind::TextLiteral { value } if value == "a"));
        assert!(matches!(&r2.kind, NodeKind::Identifier { name } if name == "b"));
    }

    #[test]
    fn template_pure_literal_is_text_node() {
        let val = lambda_value("let s be `plain`");
        assert!(matches!(&val.kind, NodeKind::TextLiteral { value } if value == "plain"));
    }

    #[test]
    fn template_leading_interp_anchors_empty_text() {
        // `{x}` -> ("" + x): primer operando forzado a TextLiteral
        let val = lambda_value("let s be `{x}`");
        let NodeKind::BinaryOp { left, operator, right } = &val.kind else {
            panic!("esperaba BinaryOp");
        };
        assert_eq!(operator, "+");
        assert!(matches!(&left.kind, NodeKind::TextLiteral { value } if value.is_empty()));
        assert!(matches!(&right.kind, NodeKind::Identifier { name } if name == "x"));
    }

    #[test]
    fn empty_template_is_empty_text() {
        let val = lambda_value("let s be ``");
        assert!(matches!(&val.kind, NodeKind::TextLiteral { value } if value.is_empty()));
    }

    #[test]
    fn plain_string_newline_still_errors_regression() {
        let err = parse_source("let s be \"a\nb\"", "<test>").unwrap_err();
        assert!(err.to_string().contains("Unterminated string"), "got: {}", err);
    }

    #[test]
    fn malformed_interp_expression_fails() {
        assert!(parse_source("let s be `{1 +}`", "<test>").is_err());
    }

    // -- Local modules (use / export) --

    #[test]
    fn use_import_parses() {
        let prog = parse_ok("use \"./orders.syn\" as orders");
        match &prog.statements[0].kind {
            NodeKind::UseImport { path, alias } => {
                assert_eq!(path, "./orders.syn");
                assert_eq!(alias, "orders");
            }
            other => panic!("esperaba UseImport, got {:?}", other),
        }
    }

    #[test]
    fn export_task_parses() {
        let prog = parse_ok("export task f()\n    give 1");
        match &prog.statements[0].kind {
            NodeKind::ExportDeclaration { declaration } => {
                assert!(matches!(declaration.kind, NodeKind::TaskDefinition { .. }));
            }
            other => panic!("esperaba ExportDeclaration, got {:?}", other),
        }
    }

    #[test]
    fn export_let_and_type_parse() {
        let p1 = parse_ok("export let x be 5");
        let NodeKind::ExportDeclaration { declaration } = &p1.statements[0].kind else {
            panic!("esperaba ExportDeclaration");
        };
        assert!(matches!(declaration.kind, NodeKind::LetBinding { .. }));
        let p2 = parse_ok("export type T\n    a: number");
        let NodeKind::ExportDeclaration { declaration } = &p2.statements[0].kind else {
            panic!("esperaba ExportDeclaration");
        };
        assert!(matches!(declaration.kind, NodeKind::TypeDefinition { .. }));
    }

    #[test]
    fn export_enum_parses() {
        let prog = parse_ok("export enum Order\n    pending\n    paid(amount)\n");
        match &prog.statements[0].kind {
            NodeKind::ExportDeclaration { declaration } => {
                assert!(matches!(declaration.kind, NodeKind::EnumDefinition { .. }));
            }
            other => panic!("esperaba ExportDeclaration envolviendo EnumDefinition, got {:?}", other),
        }
    }

    #[test]
    fn use_and_export_are_soft_keywords() {
        // `let use be 1` / `let export be 2` siguen siendo bindings normales.
        let p = parse_ok("let use be 1\nlet export be 2");
        assert!(matches!(p.statements[0].kind, NodeKind::LetBinding { .. }));
        assert!(matches!(p.statements[1].kind, NodeKind::LetBinding { .. }));
    }

    // -- Enums (sum types) --

    #[test]
    fn enum_parses_variants() {
        let p = parse_ok("enum Order\n    pending\n    paid(amount)\n    shipped(date, carrier)\n");
        match &p.statements[0].kind {
            NodeKind::EnumDefinition { name, variants } => {
                assert_eq!(name, "Order");
                assert_eq!(variants.len(), 3);
                assert_eq!(variants[0], ("pending".to_string(), vec![]));
                assert_eq!(variants[1], ("paid".to_string(), vec!["amount".to_string()]));
                assert_eq!(
                    variants[2],
                    ("shipped".to_string(), vec!["date".to_string(), "carrier".to_string()])
                );
            }
            other => panic!("esperaba EnumDefinition, got {:?}", other),
        }
    }

    #[test]
    fn enum_is_soft_keyword() {
        // `let enum be 1` sigue siendo un binding normal.
        let p = parse_ok("let enum be 1");
        assert!(matches!(p.statements[0].kind, NodeKind::LetBinding { .. }));
    }

    // -- match … otherwise --

    #[test]
    fn match_with_otherwise_parses() {
        let p = parse_ok("match x\n    is 5\n        print(\"a\")\n    otherwise\n        print(\"b\")\n");
        match &p.statements[0].kind {
            NodeKind::MatchStatement { arms, otherwise, .. } => {
                assert_eq!(arms.len(), 1);
                let body = otherwise.as_ref().expect("otherwise debería existir");
                assert_eq!(body.len(), 1);
            }
            other => panic!("esperaba MatchStatement, got {:?}", other),
        }
    }

    #[test]
    fn match_without_otherwise_parses_none() {
        let p = parse_ok("match x\n    is 5\n        print(\"a\")\n");
        match &p.statements[0].kind {
            NodeKind::MatchStatement { otherwise, .. } => assert!(otherwise.is_none()),
            other => panic!("esperaba MatchStatement, got {:?}", other),
        }
    }
}

//! Lexer de Syntecnia — Tokenizador.
//!
//! Port fiel de `syntecnia/core/lexer.py`. Decisiones de diseño:
//! - Los saltos de línea son significativos (separadores de sentencia).
//! - La indentación genera tokens INDENT/DEDENT.
//! - Comentarios con `--`.
//! - Strings con `"` o `'`.
//!
//! Paridad: Python indexa el fuente por code points. Acá trabajamos sobre un
//! `Vec<char>` para replicar exactamente `pos`/`line`/`column`/`offset` y los
//! slices de `raw`.

use std::fmt;

use crate::tokens::{keyword_lookup, Number, SourceLocation, Token, TokenType, TokenValue};

/// Error durante la tokenización, con ubicación. `Display` = "file:line:col: mensaje"
/// (igual que `str(LexerError)` en Python).
#[derive(Debug, Clone, PartialEq)]
pub struct LexerError {
    pub message: String,
    pub location: SourceLocation,
}

impl LexerError {
    pub fn new(message: impl Into<String>, location: SourceLocation) -> Self {
        Self {
            message: message.into(),
            location,
        }
    }
}

impl fmt::Display for LexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

impl std::error::Error for LexerError {}

/// `repr()` de Python para un único carácter (como en `f"...{ch!r}"`).
/// Comillas simples salvo que el char sea `'` (entonces dobles, como Python).
/// Coincide con Python para ASCII; los unicode no-imprimibles (p.ej. BOM) se
/// muestran literalmente — divergencia menor anotada.
fn py_char_repr(ch: char) -> String {
    let quote = if ch == '\'' { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    match ch {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\t' => out.push_str("\\t"),
        '\r' => out.push_str("\\r"),
        c if c == quote => {
            out.push('\\');
            out.push(c);
        }
        c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
            out.push_str(&format!("\\x{:02x}", c as u32));
        }
        c => out.push(c),
    }
    out.push(quote);
    out
}

/// Transforma código fuente Syntecnia en tokens.
pub struct Lexer {
    source: Vec<char>,
    filename: String,
    pos: usize,
    line: usize,
    column: usize,
    tokens: Vec<Token>,
    indent_stack: Vec<i64>,
    at_line_start: bool,
    paren_depth: i64,
}

impl Lexer {
    pub fn new(source: &str, filename: &str) -> Self {
        Self {
            source: source.chars().collect(),
            filename: filename.to_string(),
            pos: 0,
            line: 1,
            column: 1,
            tokens: Vec::new(),
            indent_stack: vec![0],
            at_line_start: true,
            paren_depth: 0,
        }
    }

    fn location(&self) -> SourceLocation {
        SourceLocation {
            file: self.filename.clone(),
            line: self.line,
            column: self.column,
            offset: self.pos,
        }
    }

    fn peek(&self, offset: usize) -> Option<char> {
        self.source.get(self.pos + offset).copied()
    }

    fn advance(&mut self) -> char {
        let ch = self.source[self.pos];
        self.pos += 1;
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        ch
    }

    fn at_end(&self) -> bool {
        self.pos >= self.source.len()
    }

    fn slice(&self, start: usize, end: usize) -> String {
        self.source[start..end].iter().collect()
    }

    fn emit(&mut self, ty: TokenType, value: TokenValue, location: SourceLocation, raw: String) {
        self.tokens.push(Token {
            ty,
            value,
            location,
            raw,
        });
    }

    /// Procesa la indentación al inicio de línea; emite INDENT/DEDENT.
    fn handle_indentation(&mut self) -> Result<(), LexerError> {
        let loc = self.location();
        let mut indent_level: i64 = 0;

        // Contar espacios iniciales (tab = 4)
        while !self.at_end() {
            match self.peek(0) {
                Some(' ') => {
                    indent_level += 1;
                    self.advance();
                }
                Some('\t') => {
                    indent_level += 4;
                    self.advance();
                }
                _ => break,
            }
        }

        // Saltar líneas en blanco y líneas que sólo tienen comentario
        if self.at_end() || self.peek(0) == Some('\n') {
            return Ok(());
        }
        if self.peek(0) == Some('-') && self.peek(1) == Some('-') {
            return Ok(());
        }

        let current = *self.indent_stack.last().unwrap();

        if indent_level > current {
            self.indent_stack.push(indent_level);
            self.emit(TokenType::Indent, TokenValue::Int(indent_level), loc, String::new());
        } else if indent_level < current {
            while *self.indent_stack.last().unwrap() > indent_level {
                self.indent_stack.pop();
                self.emit(
                    TokenType::Dedent,
                    TokenValue::Int(indent_level),
                    loc.clone(),
                    String::new(),
                );
            }
            let top = *self.indent_stack.last().unwrap();
            if top != indent_level {
                return Err(LexerError::new(
                    format!(
                        "Inconsistent indentation: expected {} spaces but got {}",
                        top, indent_level
                    ),
                    loc,
                ));
            }
        }
        Ok(())
    }

    /// Lee un literal de string. Soporta secuencias de escape.
    fn read_string(&mut self, quote: char) -> Result<(), LexerError> {
        let loc = self.location();
        self.advance(); // comilla de apertura
        let mut chars = String::new();
        let raw_start = self.pos - 1;

        while !self.at_end() {
            let ch = self.peek(0).unwrap();
            if ch == '\\' {
                self.advance();
                let escape = if !self.at_end() { Some(self.advance()) } else { None };
                match escape {
                    Some('n') => chars.push('\n'),
                    Some('t') => chars.push('\t'),
                    Some('r') => chars.push('\r'),
                    Some('\\') => chars.push('\\'),
                    Some('"') => chars.push('"'),
                    Some('\'') => chars.push('\''),
                    // Escape no mapeado: backslash + char (escape_map.get(escape, f'\\{escape}'))
                    Some(other) => {
                        chars.push('\\');
                        chars.push(other);
                    }
                    // Backslash al final del fuente: escape == '' -> '\\'
                    None => chars.push('\\'),
                }
            } else if ch == quote {
                self.advance(); // comilla de cierre
                let raw = self.slice(raw_start, self.pos);
                self.emit(TokenType::Text, TokenValue::Str(chars), loc, raw);
                return Ok(());
            } else if ch == '\n' {
                return Err(LexerError::new("Unterminated string (newline in string)", loc));
            } else {
                chars.push(self.advance());
            }
        }

        Err(LexerError::new("Unterminated string (reached end of file)", loc))
    }

    /// Lee un literal numérico (entero o float).
    fn read_number(&mut self) -> Result<(), LexerError> {
        let loc = self.location();
        let start = self.pos;
        let mut has_dot = false;

        while !self.at_end() {
            let ch = self.peek(0).unwrap();
            if ch == '.'
                && !has_dot
                && matches!(self.peek(1), Some(c) if c.is_ascii_digit())
            {
                has_dot = true;
                self.advance();
            } else if ch.is_ascii_digit() {
                self.advance();
            } else if ch == '_' {
                // permite estilo 1_000_000
                self.advance();
            } else {
                break;
            }
        }

        let raw = self.slice(start, self.pos);
        let clean: String = raw.chars().filter(|c| *c != '_').collect();
        let value = if has_dot {
            Number::Float(clean.parse::<f64>().map_err(|_| {
                LexerError::new(format!("Invalid float literal: {}", raw), loc.clone())
            })?)
        } else {
            // Entero de precisión arbitraria: i64 si entra, si no promueve a BigInt.
            Number::parse_int_literal(&clean)
        };
        self.emit(TokenType::Number, TokenValue::Number(value), loc, raw);
        Ok(())
    }

    /// Lee un identificador o palabra clave.
    fn read_identifier_or_keyword(&mut self) {
        let loc = self.location();
        let start = self.pos;

        while !self.at_end() {
            let ch = self.peek(0).unwrap();
            if ch.is_alphanumeric() || ch == '_' {
                self.advance();
            } else {
                break;
            }
        }

        let raw = self.slice(start, self.pos);
        let ty = keyword_lookup(&raw).unwrap_or(TokenType::Identifier);
        // Python: value = raw en ambos casos (keyword e identifier).
        self.emit(ty, TokenValue::Str(raw.clone()), loc, raw);
    }

    /// Lee un comentario (`--` hasta fin de línea).
    fn read_comment(&mut self) {
        let loc = self.location();
        let start = self.pos;
        self.advance(); // primer -
        self.advance(); // segundo -

        while !self.at_end() && self.peek(0) != Some('\n') {
            self.advance();
        }

        let raw = self.slice(start, self.pos);
        // raw[2:].strip(): saltar los dos '-' (ASCII) y recortar espacios.
        let comment_text = raw[2..].trim().to_string();
        self.emit(TokenType::Comment, TokenValue::Str(comment_text), loc, raw);
    }

    /// Tokeniza todo el fuente.
    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexerError> {
        self.tokens.clear();
        self.pos = 0;
        self.line = 1;
        self.column = 1;
        self.indent_stack = vec![0];
        self.at_line_start = true;
        self.paren_depth = 0;

        while !self.at_end() {
            let mut ch = self.peek(0).unwrap();

            // Inicio de línea (indentación)
            if self.at_line_start {
                self.at_line_start = false;
                if self.paren_depth == 0 {
                    self.handle_indentation()?;
                    if self.at_end() {
                        break;
                    }
                    match self.peek(0) {
                        Some(c) => ch = c,
                        None => break,
                    }
                }
            }

            // Saltos de línea
            if ch == '\n' {
                if self.paren_depth == 0 {
                    let loc = self.location();
                    self.advance();
                    // No emitir NEWLINEs consecutivos
                    if let Some(last) = self.tokens.last() {
                        if last.ty != TokenType::Newline {
                            self.emit(TokenType::Newline, TokenValue::None, loc, "\\n".to_string());
                        }
                    }
                } else {
                    self.advance(); // continuación implícita dentro de brackets
                }
                self.at_line_start = true;
                continue;
            }

            // Espacios (no salto de línea, no inicio de línea)
            if ch == ' ' || ch == '\t' || ch == '\r' {
                self.advance();
                continue;
            }

            // Comentarios
            if ch == '-' && self.peek(1) == Some('-') {
                self.read_comment();
                continue;
            }

            // Strings
            if ch == '"' || ch == '\'' {
                self.read_string(ch)?;
                continue;
            }

            // Números
            if ch.is_ascii_digit() {
                self.read_number()?;
                continue;
            }

            // Identificadores y palabras clave
            if ch.is_alphabetic() || ch == '_' {
                self.read_identifier_or_keyword();
                continue;
            }

            // Operadores y delimitadores
            let loc = self.location();

            // Operadores de dos caracteres
            if ch == '*' && self.peek(1) == Some('*') {
                self.advance();
                self.advance();
                self.emit(TokenType::Power, TokenValue::Str("**".into()), loc, "**".into());
            } else if ch == '=' && self.peek(1) == Some('=') {
                self.advance();
                self.advance();
                self.emit(TokenType::Equal, TokenValue::Str("==".into()), loc, "==".into());
            } else if ch == '!' && self.peek(1) == Some('=') {
                self.advance();
                self.advance();
                self.emit(TokenType::NotEqual, TokenValue::Str("!=".into()), loc, "!=".into());
            } else if ch == '<' && self.peek(1) == Some('=') {
                self.advance();
                self.advance();
                self.emit(TokenType::LessEqual, TokenValue::Str("<=".into()), loc, "<=".into());
            } else if ch == '>' && self.peek(1) == Some('=') {
                self.advance();
                self.advance();
                self.emit(
                    TokenType::GreaterEqual,
                    TokenValue::Str(">=".into()),
                    loc,
                    ">=".into(),
                );
            } else if ch == '-' && self.peek(1) == Some('>') {
                self.advance();
                self.advance();
                self.emit(TokenType::Arrow, TokenValue::Str("->".into()), loc, "->".into());
            } else if ch == '=' && self.peek(1) == Some('>') {
                self.advance();
                self.advance();
                self.emit(TokenType::FatArrow, TokenValue::Str("=>".into()), loc, "=>".into());
            } else if ch == '|' && self.peek(1) == Some('>') {
                self.advance();
                self.advance();
                self.emit(TokenType::Pipe, TokenValue::Str("|>".into()), loc, "|>".into());
            }
            // Operadores de un caracter
            else if ch == '+' {
                self.advance();
                self.emit(TokenType::Plus, TokenValue::Str("+".into()), loc, "+".into());
            } else if ch == '-' {
                self.advance();
                self.emit(TokenType::Minus, TokenValue::Str("-".into()), loc, "-".into());
            } else if ch == '*' {
                self.advance();
                self.emit(TokenType::Star, TokenValue::Str("*".into()), loc, "*".into());
            } else if ch == '/' {
                self.advance();
                self.emit(TokenType::Slash, TokenValue::Str("/".into()), loc, "/".into());
            } else if ch == '%' {
                self.advance();
                self.emit(TokenType::Percent, TokenValue::Str("%".into()), loc, "%".into());
            } else if ch == '<' {
                self.advance();
                self.emit(TokenType::Less, TokenValue::Str("<".into()), loc, "<".into());
            } else if ch == '>' {
                self.advance();
                self.emit(TokenType::Greater, TokenValue::Str(">".into()), loc, ">".into());
            } else if ch == '=' {
                self.advance();
                self.emit(TokenType::Assign, TokenValue::Str("=".into()), loc, "=".into());
            }
            // Delimitadores
            else if ch == '(' {
                self.advance();
                self.paren_depth += 1;
                self.emit(TokenType::LParen, TokenValue::Str("(".into()), loc, "(".into());
            } else if ch == ')' {
                self.advance();
                self.paren_depth = (self.paren_depth - 1).max(0);
                self.emit(TokenType::RParen, TokenValue::Str(")".into()), loc, ")".into());
            } else if ch == '[' {
                self.advance();
                self.paren_depth += 1;
                self.emit(TokenType::LBracket, TokenValue::Str("[".into()), loc, "[".into());
            } else if ch == ']' {
                self.advance();
                self.paren_depth = (self.paren_depth - 1).max(0);
                self.emit(TokenType::RBracket, TokenValue::Str("]".into()), loc, "]".into());
            } else if ch == '{' {
                self.advance();
                self.paren_depth += 1;
                self.emit(TokenType::LBrace, TokenValue::Str("{".into()), loc, "{".into());
            } else if ch == '}' {
                self.advance();
                self.paren_depth = (self.paren_depth - 1).max(0);
                self.emit(TokenType::RBrace, TokenValue::Str("}".into()), loc, "}".into());
            } else if ch == ',' {
                self.advance();
                self.emit(TokenType::Comma, TokenValue::Str(",".into()), loc, ",".into());
            } else if ch == '.' {
                self.advance();
                self.emit(TokenType::Dot, TokenValue::Str(".".into()), loc, ".".into());
            } else if ch == ':' {
                self.advance();
                self.emit(TokenType::Colon, TokenValue::Str(":".into()), loc, ":".into());
            } else {
                self.advance();
                return Err(LexerError::new(
                    format!("Unexpected character: {}", py_char_repr(ch)),
                    loc,
                ));
            }
        }

        // Emitir los DEDENT restantes
        let loc = self.location();
        while self.indent_stack.len() > 1 {
            self.indent_stack.pop();
            self.emit(TokenType::Dedent, TokenValue::Int(0), loc.clone(), String::new());
        }

        // Asegurar que el archivo termine con un token NEWLINE
        if let Some(last) = self.tokens.last() {
            if last.ty != TokenType::Newline {
                self.emit(TokenType::Newline, TokenValue::None, loc.clone(), String::new());
            }
        }

        self.emit(TokenType::Eof, TokenValue::None, loc, String::new());

        Ok(std::mem::take(&mut self.tokens))
    }

    /// Tokeniza y filtra los comentarios (útil para parsear).
    pub fn tokenize_filtered(&mut self) -> Result<Vec<Token>, LexerError> {
        Ok(self
            .tokenize()?
            .into_iter()
            .filter(|t| t.ty != TokenType::Comment)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(src: &str) -> Vec<TokenType> {
        Lexer::new(src, "<test>")
            .tokenize_filtered()
            .unwrap()
            .iter()
            .map(|t| t.ty)
            .collect()
    }

    #[test]
    fn let_binding() {
        let toks = Lexer::new("let x be 5", "<test>").tokenize_filtered().unwrap();
        assert_eq!(toks[0].ty, TokenType::Let);
        assert_eq!(toks[1].ty, TokenType::Identifier);
        assert_eq!(toks[1].value, TokenValue::Str("x".into()));
        assert_eq!(toks[2].ty, TokenType::Be);
        assert_eq!(toks[3].ty, TokenType::Number);
        assert_eq!(toks[3].value, TokenValue::Number(Number::Int(5)));
        assert_eq!(toks[4].ty, TokenType::Newline);
        assert_eq!(toks[5].ty, TokenType::Eof);
    }

    #[test]
    fn float_and_underscore() {
        let toks = Lexer::new("3.14\n1_000", "<test>").tokenize_filtered().unwrap();
        assert_eq!(toks[0].value, TokenValue::Number(Number::Float(3.14)));
        assert_eq!(toks[2].value, TokenValue::Number(Number::Int(1000)));
    }

    #[test]
    fn soft_keywords_are_identifiers() {
        // serve/route/auth NO son palabras reservadas: salen como IDENTIFIER.
        for w in ["serve", "route", "auth", "requires", "expect", "static", "from", "cors"] {
            let toks = Lexer::new(w, "<test>").tokenize_filtered().unwrap();
            assert_eq!(toks[0].ty, TokenType::Identifier, "{} debería ser IDENTIFIER", w);
        }
    }

    #[test]
    fn indentation() {
        let src = "task f()\n    give 1\n";
        let tys = types(src);
        assert!(tys.contains(&TokenType::Indent));
        assert!(tys.contains(&TokenType::Dedent));
    }

    #[test]
    fn string_escapes() {
        let toks = Lexer::new(r#""a\nb\t\"c""#, "<test>").tokenize_filtered().unwrap();
        assert_eq!(toks[0].value, TokenValue::Str("a\nb\t\"c".into()));
    }

    #[test]
    fn unterminated_string_newline() {
        let err = Lexer::new("\"abc\n\"", "<test>").tokenize().unwrap_err();
        assert!(err.message.contains("Unterminated string (newline in string)"));
    }

    #[test]
    fn unexpected_character() {
        let err = Lexer::new("@", "<test>").tokenize().unwrap_err();
        assert_eq!(err.message, "Unexpected character: '@'");
    }
}

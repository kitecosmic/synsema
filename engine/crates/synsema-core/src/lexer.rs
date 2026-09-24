//! Lexer de Synsema — Tokenizador.
//!
//! Port fiel de `synsema/core/lexer.py`. Decisiones de diseño:
//! - Los saltos de línea son significativos (separadores de sentencia).
//! - La indentación genera tokens INDENT/DEDENT.
//! - Comentarios con `--`.
//! - Strings con `"` o `'`.
//!
//! Paridad: Python indexa el fuente por code points. Acá trabajamos sobre un
//! `Vec<char>` para replicar exactamente `pos`/`line`/`column`/`offset` y los
//! slices de `raw`.

use std::fmt;

use crate::tokens::{
    keyword_lookup, Number, SourceLocation, TemplateSegment, Token, TokenType, TokenValue,
};

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

/// Transforma código fuente Synsema en tokens.
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

    /// `print(x --1)`: la pista sólo salta si todo apunta a restar un negativo — lo que sigue a
    /// `--` es un dígito o `(`, antes hay un operando en la misma línea (separado por espacio: lo
    /// pegado ya lo agarra `glued`), el bracket abierto más interno es un paréntesis y el `)` que
    /// lo cierra está en ESTA línea, después del `--` (el comentario se lo comería). Cualquier otro
    /// `--` (una nota en una llamada, lista o mapa de varias líneas, `--TODO`) es un comentario.
    fn minus_comment_looks_like_subtraction(&self) -> bool {
        if self.paren_depth <= 0 || !self.peek(2).is_some_and(|c| c.is_ascii_digit() || c == '(') {
            return false;
        }
        let Some(last) = self.tokens.last() else { return false };
        if last.location.line != self.line
            || !matches!(
                last.ty,
                TokenType::Identifier | TokenType::Number | TokenType::RParen | TokenType::RBracket
            )
        {
            return false;
        }
        let mut depth = 0usize;
        for t in self.tokens.iter().rev() {
            match t.ty {
                TokenType::RParen | TokenType::RBracket | TokenType::RBrace => depth += 1,
                TokenType::LParen | TokenType::LBracket | TokenType::LBrace => {
                    if depth == 0 {
                        return t.ty == TokenType::LParen && self.closing_paren_on_this_line();
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        false
    }

    /// ¿El `)` que cierra el paréntesis abierto está en esta línea, después del `--` actual?
    /// Cuenta paréntesis hasta el fin de línea, salteando textos entre comillas.
    fn closing_paren_on_this_line(&self) -> bool {
        let mut depth = 1i64;
        let mut i = self.pos + 2;
        let mut quote: Option<char> = None;
        while let Some(&c) = self.source.get(i) {
            if c == '\n' {
                return false;
            }
            match quote {
                Some(q) => {
                    if c == '\\' {
                        i += 1;
                    } else if c == q {
                        quote = None;
                    }
                }
                None => match c {
                    '"' | '\'' | '`' => quote = Some(c),
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return true;
                        }
                    }
                    _ => {}
                },
            }
            i += 1;
        }
        false
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

        // Saltar líneas en blanco y líneas que sólo tienen comentario. El `\r` cubre
        // los archivos CRLF de Windows: una línea en blanco ahí es "\r\n" y sin este
        // caso el dedent fantasma rompía el parser ("Unexpected token: INDENT") en
        // cualquier bloque con una línea en blanco adentro.
        if self.at_end() || self.peek(0) == Some('\n') || self.peek(0) == Some('\r') {
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

    /// `\uXXXX` y `\u{1F600}` (1 a 6 hex) (v0.6.29), mirando lo que sigue a la `u` ya
    /// consumida: `Some((carácter, cuántos chars más consumir))` si es un escape válido. Si no
    /// lo es (`"C:\users"`), `None` y queda literal, como antes. `\x` NO es escape (una ruta
    /// `C:\build\x64` o una regex `a\x2eb` quedan como estaban); en un backtick `\u{…}` tampoco
    /// (ahí `{…}` es interpolación: `x\u{a}y` sigue interpolando `a`), `braces = false`.
    fn unicode_escape(&self, braces: bool) -> Option<(char, usize)> {
        let hex_at = |i: usize| self.peek(i).filter(|c| c.is_ascii_hexdigit());
        if self.peek(0) == Some('{') {
            if !braces {
                return None;
            }
            let mut n = 1;
            let mut digits = String::new();
            while let Some(c) = hex_at(n) {
                digits.push(c);
                n += 1;
                if digits.len() > 6 {
                    return None;
                }
            }
            if digits.is_empty() || self.peek(n) != Some('}') {
                return None;
            }
            let v = u32::from_str_radix(&digits, 16).ok()?;
            return char::from_u32(v).map(|c| (c, n + 1));
        }
        let hex4 = |from: usize| -> Option<u32> {
            let digits: String = (from..from + 4).map(hex_at).collect::<Option<String>>()?;
            u32::from_str_radix(&digits, 16).ok()
        };
        let v = hex4(0)?;
        // Un par sustituto (`\uD83D\uDE00`, como lo escriben JSON y JavaScript) es UN carácter.
        if (0xD800..0xDC00).contains(&v) && self.peek(4) == Some('\\') && self.peek(5) == Some('u') {
            let lo = hex4(6)?;
            if (0xDC00..0xE000).contains(&lo) {
                return char::from_u32(0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00)).map(|c| (c, 10));
            }
        }
        char::from_u32(v).map(|c| (c, 4))
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
                    Some('u') if self.unicode_escape(true).is_some() => {
                        let (ch, n) = self.unicode_escape(true).unwrap();
                        for _ in 0..n {
                            self.advance();
                        }
                        chars.push(ch);
                    }
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

    /// Lee un literal de template con backtick: interpolación + multilínea.
    ///
    /// Parte el cuerpo del backtick en segmentos ordenados y emite UN token
    /// TEMPLATE. Espeja `_read_template` del oráculo Python: mismos escapes (los
    /// de string + ``\``` `` → backtick literal y ``\{`` → `{` literal), newlines
    /// reales permitidos, y el split de los holes `{ … }` balancea llaves y se
    /// salta strings anidados (§6) para que un `}` dentro de "…"/'…'/`…` NO cierre
    /// la interpolación. El desugar a la cadena `+` ocurre después, en el parser.
    fn read_template(&mut self) -> Result<(), LexerError> {
        let loc = self.location();
        let raw_start = self.pos;
        self.advance(); // backtick de apertura
        let mut segments: Vec<TemplateSegment> = Vec::new();
        let mut chars = String::new();

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
                    Some('`') => chars.push('`'),
                    Some('{') => chars.push('{'),
                    Some('u') if self.unicode_escape(false).is_some() => {
                        let (ch, n) = self.unicode_escape(false).unwrap();
                        for _ in 0..n {
                            self.advance();
                        }
                        chars.push(ch);
                    }
                    // Escape no mapeado: backslash + char (igual que read_string).
                    Some(other) => {
                        chars.push('\\');
                        chars.push(other);
                    }
                    // Backslash al final del fuente.
                    None => chars.push('\\'),
                }
            } else if ch == '`' {
                self.advance(); // backtick de cierre
                if !chars.is_empty() {
                    segments.push(TemplateSegment::Literal(std::mem::take(&mut chars)));
                }
                let raw = self.slice(raw_start, self.pos);
                self.emit(TokenType::Template, TokenValue::Template(segments), loc, raw);
                return Ok(());
            } else if ch == '{' {
                let interp_loc = self.location();
                self.advance(); // '{'
                if !chars.is_empty() {
                    segments.push(TemplateSegment::Literal(std::mem::take(&mut chars)));
                }
                // Capturar el source balanceado del hole (§6): cuenta profundidad
                // de llaves, pero copia los strings anidados verbatim para que sus
                // llaves/comillas no cuenten en el balance.
                let mut expr_src = String::new();
                let mut depth: i32 = 1;
                let mut closed = false;
                while !self.at_end() {
                    let c = self.peek(0).unwrap();
                    if c == '"' || c == '\'' || c == '`' {
                        let delim = self.advance();
                        expr_src.push(delim);
                        while !self.at_end() {
                            let cc = self.peek(0).unwrap();
                            if cc == '\\' {
                                expr_src.push(self.advance());
                                if !self.at_end() {
                                    expr_src.push(self.advance());
                                }
                            } else if cc == delim {
                                expr_src.push(self.advance());
                                break;
                            } else {
                                expr_src.push(self.advance());
                            }
                        }
                        continue;
                    }
                    if c == '{' {
                        depth += 1;
                        expr_src.push(self.advance());
                    } else if c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            self.advance(); // '}' de cierre
                            closed = true;
                            break;
                        }
                        expr_src.push(self.advance());
                    } else {
                        expr_src.push(self.advance());
                    }
                }
                if !closed {
                    return Err(LexerError::new(
                        "Unterminated template (reached end of file)",
                        loc,
                    ));
                }
                segments.push(TemplateSegment::Interp(expr_src, interp_loc));
            } else {
                chars.push(self.advance());
            }
        }

        Err(LexerError::new("Unterminated template (reached end of file)", loc))
    }

    /// Lee un literal numérico: entero (decimal, `0x…`, `0b…`), float (`1.5`, `1e-9`,
    /// `1.5e3`) o decimal (`1.50d`). `_` separa dígitos en todas las formas.
    fn read_number(&mut self) -> Result<(), LexerError> {
        /// `_` sólo entre dos dígitos (como Python): `1_000`, no `1__0`, `1_`, `1_.5` ni `1e_3`.
        /// Tras el prefijo de base (`0x_1f`) también vale, como en Python.
        fn underscores_ok(s: &str, radix: u32, after_prefix: bool) -> bool {
            let c: Vec<char> = s.chars().collect();
            (0..c.len()).all(|i| {
                c[i] != '_'
                    || ((i > 0 && c[i - 1].is_digit(radix)) || (i == 0 && after_prefix))
                        && c.get(i + 1).is_some_and(|n| n.is_digit(radix))
            })
        }
        let loc = self.location();
        let start = self.pos;
        let mut has_dot = false;

        // `0x…` / `0b…` → entero exacto (v0.6.29). Hace falta un dígito válido después
        // del prefijo: `0x` solo, o `0xg`, es error y no "0 seguido de x".
        if self.peek(0) == Some('0') {
            if let Some(p) = self.peek(1) {
                let radix = match p {
                    'x' | 'X' => Some(16),
                    'o' | 'O' => Some(8),
                    'b' | 'B' => Some(2),
                    _ => None,
                };
                if let Some(radix) = radix {
                    self.advance();
                    self.advance();
                    let digits_start = self.pos;
                    while let Some(c) = self.peek(0) {
                        if c.is_digit(radix) || c == '_' {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let raw = self.slice(start, self.pos);
                    let clean: String =
                        self.slice(digits_start, self.pos).chars().filter(|c| *c != '_').collect();
                    let bad_tail = matches!(self.peek(0), Some(c) if c.is_alphanumeric());
                    let (name, what) = match radix {
                        16 => ("hex", "hex (0-9, a-f)"),
                        8 => ("octal", "octal (0-7)"),
                        _ => ("binary", "binary (0 or 1)"),
                    };
                    if clean.is_empty() || bad_tail {
                        return Err(LexerError::new(
                            format!("Invalid {} literal: {} — expected {} digits after the prefix",
                                name,
                                if bad_tail { format!("{}{}", raw, self.peek(0).unwrap()) } else { raw.clone() },
                                what),
                            loc,
                        ));
                    }
                    if !underscores_ok(&raw[2..], radix, true) {
                        return Err(LexerError::new(
                            format!("Invalid {} literal: {} — `_` goes only between two digits (1_000)", name, raw),
                            loc,
                        ));
                    }
                    let value = Number::from_bigint(
                        num_bigint::BigInt::parse_bytes(clean.as_bytes(), radix).unwrap_or_default(),
                    );
                    self.emit(TokenType::Number, TokenValue::Number(value), loc, raw);
                    return Ok(());
                }
            }
        }

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

        // Exponente → float, como Python: `1e3`, `1e-9`, `1.5E+3`. Sólo si lo sigue un
        // dígito (con signo opcional): `2e` o `2ex` siguen siendo número + identificador.
        let mut has_exp = false;
        if matches!(self.peek(0), Some('e') | Some('E')) {
            let digit_at = if matches!(self.peek(1), Some('+') | Some('-')) { 2 } else { 1 };
            if matches!(self.peek(digit_at), Some(c) if c.is_ascii_digit()) {
                has_exp = true;
                for _ in 0..digit_at {
                    self.advance();
                }
                while matches!(self.peek(0), Some(c) if c.is_ascii_digit() || c == '_') {
                    self.advance();
                }
            }
        }

        // Sufijo `d` → literal Decimal exacto (1.50d, 100d), pero SÓLO si no lo sigue
        // un char de continuación de identificador: `1.50d`→Decimal, `1.50 d`→número
        // + ident, `1.50dx`→número + ident `dx`.
        let is_decimal = !has_exp
            && self.peek(0) == Some('d')
            && !matches!(self.peek(1), Some(c) if c.is_alphanumeric() || c == '_');
        if is_decimal {
            self.advance(); // consume el sufijo 'd'
        }

        let raw = self.slice(start, self.pos);
        if !underscores_ok(&raw, 10, false) {
            return Err(LexerError::new(
                format!("Invalid number literal: {} — `_` goes only between two digits (1_000, 1_000.5)", raw),
                loc,
            ));
        }
        // dígitos sin separadores `_` ni el sufijo `d`.
        let clean: String = raw.chars().filter(|c| *c != '_' && *c != 'd').collect();
        let value = if is_decimal {
            // Cualquier cantidad de dígitos (v0.6.29): más de 28 es un decimal grande, exacto.
            Number::parse_decimal(&clean).ok_or_else(|| {
                LexerError::new(format!("Invalid decimal literal: {}", raw), loc.clone())
            })?
        } else if has_dot || has_exp {
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

            // Comentarios: `--` abre un comentario al inicio de línea o después de un
            // espacio. Pegado a un operando (`5--1`) no es un comentario silencioso que
            // corta la expresión: es un error que muestra las dos lecturas (v0.6.29).
            if ch == '-' && self.peek(1) == Some('-') {
                let prev = if self.pos == 0 { None } else { self.source.get(self.pos - 1).copied() };
                let glued = matches!(prev, Some(c) if !c.is_whitespace() && !matches!(c, '(' | '[' | '{' | ','));
                // Pegado a un valor, `--` es error SÓLO si lo que sigue es un número o `(`: `5--1`
                // y `x--(y)` son la ambigüedad real (un resultado aritmético silencioso). El resto
                // (`print(1)--nota`, `x--nota`, `"a"--nota`) es un comentario, como en v0.6.28.
                let arithmetic_after = self.peek(2).is_some_and(|c| c.is_ascii_digit() || c == '(');
                if glued && arithmetic_after {
                    return Err(LexerError::new(
                        "`--` right after a value: a comment needs a space before `--`, and a negative operand needs a space after the operator (write `5 - -1`, or `5 -- comment`)",
                        self.location(),
                    ));
                }
                // `print(x --1)`: con un paréntesis abierto, `--` pegado a lo que sigue casi seguro
                // quería restar un negativo; como comentario se come el `)` y el error sale lejos.
                if self.minus_comment_looks_like_subtraction() {
                    return Err(LexerError::new(
                        "`--` starts a comment (the rest of the line, including a closing `)`, is ignored) — to subtract a negative write `x - -1`; a comment inside parentheses needs a space after `--`",
                        self.location(),
                    ));
                }
                self.read_comment();
                continue;
            }

            // Strings
            if ch == '"' || ch == '\'' {
                self.read_string(ch)?;
                continue;
            }

            // Strings de template con backtick (interpolación + multilínea)
            if ch == '`' {
                self.read_template()?;
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
            } else if ch == '/' && self.peek(1) == Some('/') {
                self.advance();
                self.advance();
                self.emit(TokenType::FloorDiv, TokenValue::Str("//".into()), loc, "//".into());
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
                // `...` (EXACTAMENTE tres puntos) → Spread; cualquier otra cosa → Dot.
                // No se introduce `..`: dos puntos siguen siendo Dot+Dot, y `a.b.c`
                // (property chain) sigue lexeando como Dot/Dot (G6). Para `....` se emite
                // Spread + Dot (3 puntos + 1).
                if self.peek(1) == Some('.') && self.peek(2) == Some('.') {
                    self.advance();
                    self.advance();
                    self.advance();
                    self.emit(TokenType::Spread, TokenValue::Str("...".into()), loc, "...".into());
                } else {
                    self.advance();
                    self.emit(TokenType::Dot, TokenValue::Str(".".into()), loc, ".".into());
                }
            } else if ch == ':' {
                self.advance();
                self.emit(TokenType::Colon, TokenValue::Str(":".into()), loc, ":".into());
            } else {
                self.advance();
                let hint = match ch {
                    '?' => " — no `c ? a : b`: the inline form is `when c then a otherwise b`",
                    '&' | '|' => " — the logical operators are `and` / `or`",
                    ';' => " — one statement per line (no `;`)",
                    _ => "",
                };
                return Err(LexerError::new(
                    format!("Unexpected character: {}{}", py_char_repr(ch), hint),
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
    // El literal "3.14" es el INPUT del lexer bajo prueba, no una aproximación de π.
    #[allow(clippy::approx_constant)]
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

    // -- Backtick templates --

    fn first_template(src: &str) -> Vec<TemplateSegment> {
        let toks = Lexer::new(src, "<test>").tokenize_filtered().unwrap();
        let t = toks
            .iter()
            .find(|t| t.ty == TokenType::Template)
            .expect("no hay token TEMPLATE");
        match &t.value {
            TokenValue::Template(segs) => segs.clone(),
            _ => panic!("TEMPLATE sin segmentos"),
        }
    }

    #[test]
    fn template_lexes_segments() {
        let segs = first_template("`a{b}c`");
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0], TemplateSegment::Literal("a".into()));
        match &segs[1] {
            TemplateSegment::Interp(src, _) => assert_eq!(src, "b"),
            _ => panic!("esperaba Interp"),
        }
        assert_eq!(segs[2], TemplateSegment::Literal("c".into()));
    }

    #[test]
    fn template_pure_literal() {
        assert_eq!(first_template("`plain`"), vec![TemplateSegment::Literal("plain".into())]);
    }

    #[test]
    fn template_multiline() {
        assert_eq!(first_template("`a\nb`"), vec![TemplateSegment::Literal("a\nb".into())]);
    }

    #[test]
    fn template_escapes_brace_and_backtick() {
        // \{ -> '{', \` -> backtick, \n -> newline (mismo set que los strings + \` \{)
        let segs = first_template(r"`x\{y\`z\n`");
        assert_eq!(segs, vec![TemplateSegment::Literal("x{y`z\n".into())]);
    }

    #[test]
    fn template_nested_string_in_interp() {
        // el `}` dentro de "}" NO cierra la interpolación (§6)
        let segs = first_template("`x{f(\"}\")}`");
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0], TemplateSegment::Literal("x".into()));
        match &segs[1] {
            TemplateSegment::Interp(src, _) => assert_eq!(src, "f(\"}\")"),
            _ => panic!("esperaba Interp"),
        }
    }

    #[test]
    fn template_nested_braces_in_interp() {
        // un map literal dentro de la interpolación: llaves balanceadas (§6)
        let segs = first_template("`{ {\"a\": 1} }`");
        assert_eq!(segs.len(), 1);
        match &segs[0] {
            TemplateSegment::Interp(src, _) => assert_eq!(src, " {\"a\": 1} "),
            _ => panic!("esperaba Interp"),
        }
    }

    #[test]
    fn template_unterminated_eof() {
        let err = Lexer::new("`abc", "<test>").tokenize().unwrap_err();
        assert!(err.message.contains("Unterminated template (reached end of file)"));
    }

    #[test]
    fn template_unterminated_interp_eof() {
        let err = Lexer::new("`a{b", "<test>").tokenize().unwrap_err();
        assert!(err.message.contains("Unterminated template (reached end of file)"));
    }

    #[test]
    fn plain_string_still_text_regression() {
        // regresión: "..." sigue siendo TEXT literal, sin interpolar
        let toks = Lexer::new(r#""{literal}""#, "<test>").tokenize_filtered().unwrap();
        assert_eq!(toks[0].ty, TokenType::Text);
        assert_eq!(toks[0].value, TokenValue::Str("{literal}".into()));
    }
}

"""
Synsema Lexer — Tokenizer.

Converts source text into a stream of tokens. Key design decisions:
- Newlines are significant (statement separators, like Python)
- Indentation is tracked for blocks (INDENT/DEDENT tokens)
- Comments start with '--' (double dash)
- Strings use double quotes (") or single quotes (')
- No semicolons, no curly braces for blocks
- Keywords are English words that read naturally
"""

from typing import List, Iterator, Optional
from .tokens import Token, TokenType, SourceLocation, KEYWORDS


class LexerError(Exception):
    """Error during tokenization with full location info."""

    def __init__(self, message: str, location: SourceLocation):
        self.location = location
        super().__init__(f"{location}: {message}")


class Lexer:
    """
    Transforms Synsema source code into tokens.

    The lexer handles:
    - Significant whitespace (indentation-based blocks)
    - Natural language keywords
    - String interpolation markers
    - Full source location tracking for observability
    """

    def __init__(self, source: str, filename: str = "<stdin>"):
        self.source = source
        self.filename = filename
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []
        self.indent_stack: List[int] = [0]  # stack of indentation levels
        self.at_line_start = True
        self.paren_depth = 0  # track () [] {} nesting for implicit line continuation

    def _location(self) -> SourceLocation:
        return SourceLocation(
            file=self.filename,
            line=self.line,
            column=self.column,
            offset=self.pos,
        )

    def _peek(self, offset: int = 0) -> Optional[str]:
        idx = self.pos + offset
        if idx < len(self.source):
            return self.source[idx]
        return None

    def _advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def _at_end(self) -> bool:
        return self.pos >= len(self.source)

    def _emit(self, token_type: TokenType, value: any, start_loc: SourceLocation, raw: str):
        self.tokens.append(Token(
            type=token_type,
            value=value,
            location=start_loc,
            raw=raw,
        ))

    def _skip_whitespace_on_line(self) -> int:
        """Skip spaces/tabs on current line, return count of spaces (tabs = 4 spaces)."""
        count = 0
        while not self._at_end() and self._peek() in (' ', '\t'):
            ch = self._advance()
            count += 4 if ch == '\t' else 1
        return count

    def _handle_indentation(self):
        """Process indentation at the start of a line, emit INDENT/DEDENT tokens."""
        loc = self._location()
        indent_level = 0

        # Count leading whitespace
        while not self._at_end() and self._peek() in (' ', '\t'):
            ch = self.source[self.pos]
            indent_level += 4 if ch == '\t' else 1
            self._advance()

        # Skip blank lines and comment-only lines
        if self._at_end() or self._peek() == '\n':
            return
        if self._peek() == '-' and self._peek(1) == '-':
            return

        current = self.indent_stack[-1]

        if indent_level > current:
            self.indent_stack.append(indent_level)
            self._emit(TokenType.INDENT, indent_level, loc, "")
        elif indent_level < current:
            while self.indent_stack[-1] > indent_level:
                self.indent_stack.pop()
                self._emit(TokenType.DEDENT, indent_level, loc, "")
            if self.indent_stack[-1] != indent_level:
                raise LexerError(
                    f"Inconsistent indentation: expected {self.indent_stack[-1]} "
                    f"spaces but got {indent_level}",
                    loc,
                )

    def _read_string(self, quote: str) -> Token:
        """Read a string literal. Supports escape sequences."""
        loc = self._location()
        self._advance()  # consume opening quote
        chars = []
        raw_start = self.pos - 1

        while not self._at_end():
            ch = self._peek()
            if ch == '\\':
                self._advance()
                escape = self._advance() if not self._at_end() else ''
                escape_map = {
                    'n': '\n', 't': '\t', 'r': '\r',
                    '\\': '\\', '"': '"', "'": "'",
                }
                chars.append(escape_map.get(escape, f'\\{escape}'))
            elif ch == quote:
                self._advance()  # consume closing quote
                raw = self.source[raw_start:self.pos]
                value = ''.join(chars)
                self._emit(TokenType.TEXT, value, loc, raw)
                return
            elif ch == '\n':
                raise LexerError("Unterminated string (newline in string)", loc)
            else:
                chars.append(self._advance())

        raise LexerError("Unterminated string (reached end of file)", loc)

    def _read_number(self) -> Token:
        """Read a numeric literal (integer or float)."""
        loc = self._location()
        start = self.pos
        has_dot = False

        while not self._at_end():
            ch = self._peek()
            if ch == '.' and not has_dot and self._peek(1) and self._peek(1).isdigit():
                has_dot = True
                self._advance()
            elif ch.isdigit():
                self._advance()
            elif ch == '_':  # allow 1_000_000 style
                self._advance()
            else:
                break

        raw = self.source[start:self.pos]
        clean = raw.replace('_', '')
        value = float(clean) if has_dot else int(clean)
        self._emit(TokenType.NUMBER, value, loc, raw)

    def _read_identifier_or_keyword(self) -> Token:
        """Read an identifier or keyword."""
        loc = self._location()
        start = self.pos

        while not self._at_end():
            ch = self._peek()
            if ch.isalnum() or ch == '_':
                self._advance()
            else:
                break

        raw = self.source[start:self.pos]

        # Check for two-word keywords: "and_then", "wait_for"
        token_type = KEYWORDS.get(raw, TokenType.IDENTIFIER)
        value = raw if token_type == TokenType.IDENTIFIER else raw

        self._emit(token_type, value, loc, raw)

    def _read_comment(self):
        """Read a comment (-- to end of line). Comments are preserved for observability."""
        loc = self._location()
        start = self.pos
        self._advance()  # first -
        self._advance()  # second -

        while not self._at_end() and self._peek() != '\n':
            self._advance()

        raw = self.source[start:self.pos]
        comment_text = raw[2:].strip()
        self._emit(TokenType.COMMENT, comment_text, loc, raw)

    def tokenize(self) -> List[Token]:
        """
        Tokenize the entire source into a list of tokens.

        Returns a list of Token objects with full source location
        information for every token — enabling complete traceability.
        """
        self.tokens = []
        self.pos = 0
        self.line = 1
        self.column = 1
        self.indent_stack = [0]
        self.at_line_start = True
        self.paren_depth = 0

        while not self._at_end():
            ch = self._peek()

            # Handle line starts (indentation)
            if self.at_line_start:
                self.at_line_start = False
                if self.paren_depth == 0:
                    self._handle_indentation()
                    if self._at_end():
                        break
                    ch = self._peek()
                    if ch is None:
                        break

            # Newlines
            if ch == '\n':
                if self.paren_depth == 0:
                    loc = self._location()
                    self._advance()
                    # Don't emit consecutive newlines
                    if self.tokens and self.tokens[-1].type != TokenType.NEWLINE:
                        self._emit(TokenType.NEWLINE, None, loc, "\\n")
                else:
                    self._advance()  # implicit line continuation inside brackets
                self.at_line_start = True
                continue

            # Whitespace (non-newline, non-line-start)
            if ch in (' ', '\t', '\r'):
                self._advance()
                continue

            # Comments
            if ch == '-' and self._peek(1) == '-':
                self._read_comment()
                continue

            # Strings
            if ch in ('"', "'"):
                self._read_string(ch)
                continue

            # Numbers
            if ch.isdigit():
                self._read_number()
                continue

            # Identifiers and keywords
            if ch.isalpha() or ch == '_':
                self._read_identifier_or_keyword()
                continue

            # Operators and delimiters
            loc = self._location()

            # Two-character operators
            if ch == '*' and self._peek(1) == '*':
                self._advance(); self._advance()
                self._emit(TokenType.POWER, "**", loc, "**")
            elif ch == '=' and self._peek(1) == '=':
                self._advance(); self._advance()
                self._emit(TokenType.EQUAL, "==", loc, "==")
            elif ch == '!' and self._peek(1) == '=':
                self._advance(); self._advance()
                self._emit(TokenType.NOT_EQUAL, "!=", loc, "!=")
            elif ch == '<' and self._peek(1) == '=':
                self._advance(); self._advance()
                self._emit(TokenType.LESS_EQUAL, "<=", loc, "<=")
            elif ch == '>' and self._peek(1) == '=':
                self._advance(); self._advance()
                self._emit(TokenType.GREATER_EQUAL, ">=", loc, ">=")
            elif ch == '-' and self._peek(1) == '>':
                self._advance(); self._advance()
                self._emit(TokenType.ARROW, "->", loc, "->")
            elif ch == '=' and self._peek(1) == '>':
                self._advance(); self._advance()
                self._emit(TokenType.FAT_ARROW, "=>", loc, "=>")
            elif ch == '|' and self._peek(1) == '>':
                self._advance(); self._advance()
                self._emit(TokenType.PIPE, "|>", loc, "|>")

            # Single-character operators
            elif ch == '+':
                self._advance()
                self._emit(TokenType.PLUS, "+", loc, "+")
            elif ch == '-':
                self._advance()
                self._emit(TokenType.MINUS, "-", loc, "-")
            elif ch == '*':
                self._advance()
                self._emit(TokenType.STAR, "*", loc, "*")
            elif ch == '/':
                self._advance()
                self._emit(TokenType.SLASH, "/", loc, "/")
            elif ch == '%':
                self._advance()
                self._emit(TokenType.PERCENT, "%", loc, "%")
            elif ch == '<':
                self._advance()
                self._emit(TokenType.LESS, "<", loc, "<")
            elif ch == '>':
                self._advance()
                self._emit(TokenType.GREATER, ">", loc, ">")
            elif ch == '=':
                self._advance()
                self._emit(TokenType.ASSIGN, "=", loc, "=")

            # Delimiters
            elif ch == '(':
                self._advance()
                self.paren_depth += 1
                self._emit(TokenType.LPAREN, "(", loc, "(")
            elif ch == ')':
                self._advance()
                self.paren_depth = max(0, self.paren_depth - 1)
                self._emit(TokenType.RPAREN, ")", loc, ")")
            elif ch == '[':
                self._advance()
                self.paren_depth += 1
                self._emit(TokenType.LBRACKET, "[", loc, "[")
            elif ch == ']':
                self._advance()
                self.paren_depth = max(0, self.paren_depth - 1)
                self._emit(TokenType.RBRACKET, "]", loc, "]")
            elif ch == '{':
                self._advance()
                self.paren_depth += 1
                self._emit(TokenType.LBRACE, "{", loc, "{")
            elif ch == '}':
                self._advance()
                self.paren_depth = max(0, self.paren_depth - 1)
                self._emit(TokenType.RBRACE, "}", loc, "}")
            elif ch == ',':
                self._advance()
                self._emit(TokenType.COMMA, ",", loc, ",")
            elif ch == '.':
                self._advance()
                self._emit(TokenType.DOT, ".", loc, ".")
            elif ch == ':':
                self._advance()
                self._emit(TokenType.COLON, ":", loc, ":")
            else:
                self._advance()
                raise LexerError(f"Unexpected character: {ch!r}", loc)

        # Emit remaining DEDENT tokens
        loc = self._location()
        while len(self.indent_stack) > 1:
            self.indent_stack.pop()
            self._emit(TokenType.DEDENT, 0, loc, "")

        # Ensure file ends with newline token
        if self.tokens and self.tokens[-1].type != TokenType.NEWLINE:
            self._emit(TokenType.NEWLINE, None, loc, "")

        self._emit(TokenType.EOF, None, loc, "")

        return self.tokens

    def tokenize_filtered(self) -> List[Token]:
        """Tokenize and filter out comments (useful for parsing)."""
        return [t for t in self.tokenize() if t.type != TokenType.COMMENT]

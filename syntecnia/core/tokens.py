"""
Syntecnia Token Definitions.

Tokens are the atomic units of the language. Syntecnia's tokens reflect
its design philosophy: readable, flat, intention-based.

The language uses natural-flow keywords instead of traditional programming
constructs:
    - 'when' instead of 'if'
    - 'otherwise' instead of 'else'
    - 'each' instead of 'for'
    - 'task' instead of 'function'
    - 'require' for capability declarations
    - 'approve' for human intervention points
    - 'agent' for agent definitions
    - 'share' for blackboard/shared state
    - 'reason' for LLM-powered reasoning blocks
    - 'invariant' for runtime guarantees
    - 'intent' for declaring the purpose of an operation
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Any, Optional


class TokenType(Enum):
    # -- Literals --
    NUMBER = auto()          # 42, 3.14
    TEXT = auto()             # "hello", 'world'
    BOOL_TRUE = auto()       # true
    BOOL_FALSE = auto()      # false
    NOTHING = auto()         # nothing (null equivalent)
    IDENTIFIER = auto()      # variable/function names

    # -- Flow keywords (replace traditional if/else/for) --
    WHEN = auto()            # conditional: when condition
    OTHERWISE = auto()       # else branch: otherwise
    EACH = auto()            # iteration: each item in list
    WHILE = auto()           # loop: while condition
    MATCH = auto()           # pattern matching: match value
    IS = auto()              # match arm: is pattern
    THEN = auto()            # consequence: then action
    AND_THEN = auto()        # sequential step: and then
    STOP = auto()            # early exit: stop
    REPEAT = auto()          # loop restart: repeat
    IN = auto()              # membership: item in collection
    WITH = auto()            # context/binding: with x as y

    # -- Definition keywords --
    TASK = auto()            # function: task name(params)
    GIVE = auto()            # return: give value
    LET = auto()             # binding: let x be value
    BE = auto()              # assignment: let x be 5
    SET = auto()             # mutation: set x to 5
    TO = auto()              # target: set x to value
    AS = auto()              # aliasing: with x as y
    OF = auto()              # property access: name of person
    TYPE = auto()            # type definition: type Name

    # -- Agent keywords --
    AGENT = auto()           # agent definition
    SPAWN = auto()           # create sub-agent
    SHARE = auto()           # publish to blackboard
    OBSERVE = auto()         # read from blackboard
    STATE = auto()           # agent state declaration
    SIGNAL = auto()          # inter-agent signal
    WAIT_FOR = auto()        # wait for signal/condition

    # -- Capability & Security keywords --
    REQUIRE = auto()         # capability declaration
    ALLOW = auto()           # grant permission
    DENY = auto()            # revoke permission
    SANDBOX = auto()         # sandboxed execution block
    VERIFY = auto()          # verify invariant

    # -- Human interaction keywords --
    APPROVE = auto()         # human approval point
    SHOW = auto()            # display/preview to human
    ASK = auto()             # ask human for input
    CONFIRM = auto()         # confirmation checkpoint

    # -- Reasoning keywords (LLM integration) --
    REASON = auto()          # LLM reasoning block
    INTENT = auto()          # declare operation intent
    INVARIANT = auto()       # runtime guarantee
    DECIDE = auto()          # LLM-powered decision
    ANALYZE = auto()         # LLM analysis
    GENERATE = auto()        # LLM content generation

    # -- Error handling keywords --
    TRY = auto()             # try block
    RECOVER = auto()         # catch/recover block

    # -- HTTP server SOFT keywords --
    # These are NOT in KEYWORDS: the lexer emits them as IDENTIFIER and the
    # parser recognizes them only at the start of their construction (serve on
    # N, route "...", requires auth, expect body {...}) via fixed lookahead.
    # The enum members are kept as documentation of the reserved-by-context set.
    SERVE = auto()           # serve on PORT — start an HTTP server
    ON = auto()              # serve on PORT
    ROUTE = auto()           # route "GET /path" — define a route
    AUTH = auto()            # auth with <task> / requires auth
    REQUIRES = auto()        # route ... requires auth
    EXPECT = auto()          # expect body {field: type} — input validation

    # -- Observability keywords --
    TRACE = auto()           # tracing block
    LOG = auto()             # log emission
    MEASURE = auto()         # performance measurement
    CHECKPOINT = auto()      # state snapshot

    # -- Operators --
    PLUS = auto()            # +
    MINUS = auto()           # -
    STAR = auto()            # *
    SLASH = auto()           # /
    PERCENT = auto()         # %
    POWER = auto()           # **

    EQUAL = auto()           # ==
    NOT_EQUAL = auto()       # !=
    LESS = auto()            # <
    GREATER = auto()         # >
    LESS_EQUAL = auto()      # <=
    GREATER_EQUAL = auto()   # >=

    AND = auto()             # and
    OR = auto()              # or
    NOT = auto()             # not

    ASSIGN = auto()          # =
    ARROW = auto()           # ->
    FAT_ARROW = auto()       # =>
    PIPE = auto()            # |>

    # -- Delimiters --
    LPAREN = auto()          # (
    RPAREN = auto()          # )
    LBRACKET = auto()        # [
    RBRACKET = auto()        # ]
    LBRACE = auto()          # {  (used only for maps)
    RBRACE = auto()          # }
    COMMA = auto()           # ,
    DOT = auto()             # .
    COLON = auto()           # :
    NEWLINE = auto()         # \n (significant in Syntecnia)
    INDENT = auto()          # indentation increase
    DEDENT = auto()          # indentation decrease

    # -- Special --
    COMMENT = auto()         # -- comment
    EOF = auto()             # end of file
    ERROR = auto()           # lexer error token


# Keywords mapping
KEYWORDS = {
    # Flow
    "when": TokenType.WHEN,
    "otherwise": TokenType.OTHERWISE,
    "each": TokenType.EACH,
    "while": TokenType.WHILE,
    "match": TokenType.MATCH,
    "is": TokenType.IS,
    "then": TokenType.THEN,
    "and_then": TokenType.AND_THEN,
    "stop": TokenType.STOP,
    "repeat": TokenType.REPEAT,
    "in": TokenType.IN,
    "with": TokenType.WITH,

    # Definitions
    "task": TokenType.TASK,
    "give": TokenType.GIVE,
    "let": TokenType.LET,
    "be": TokenType.BE,
    "set": TokenType.SET,
    "to": TokenType.TO,
    "as": TokenType.AS,
    "of": TokenType.OF,
    "type": TokenType.TYPE,

    # Agent
    "agent": TokenType.AGENT,
    "spawn": TokenType.SPAWN,
    "share": TokenType.SHARE,
    "observe": TokenType.OBSERVE,
    "state": TokenType.STATE,
    "signal": TokenType.SIGNAL,
    "wait_for": TokenType.WAIT_FOR,

    # Capabilities
    "require": TokenType.REQUIRE,
    "allow": TokenType.ALLOW,
    "deny": TokenType.DENY,
    "sandbox": TokenType.SANDBOX,
    "verify": TokenType.VERIFY,

    # Human
    "approve": TokenType.APPROVE,
    "show": TokenType.SHOW,
    "ask": TokenType.ASK,
    "confirm": TokenType.CONFIRM,

    # Reasoning
    "reason": TokenType.REASON,
    "intent": TokenType.INTENT,
    "invariant": TokenType.INVARIANT,
    "decide": TokenType.DECIDE,
    "analyze": TokenType.ANALYZE,
    "generate": TokenType.GENERATE,

    # Observability
    "trace": TokenType.TRACE,
    "log": TokenType.LOG,
    "measure": TokenType.MEASURE,
    "checkpoint": TokenType.CHECKPOINT,

    # Error handling
    "try": TokenType.TRY,
    "recover": TokenType.RECOVER,

    # NOTE: the HTTP-server words (serve, on, route, auth, requires, expect)
    # are intentionally NOT reserved. They are *soft keywords*: the parser
    # recognizes them only at the start of their construction (serve on N,
    # route "...", requires auth, expect body {...}) via fixed lookahead.
    # Everywhere else they are ordinary identifiers, so `let route be "/x"`
    # and `task auth(x)` are valid.

    # Literals
    "true": TokenType.BOOL_TRUE,
    "false": TokenType.BOOL_FALSE,
    "nothing": TokenType.NOTHING,

    # Logical operators
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
}


@dataclass(frozen=True)
class SourceLocation:
    """Exact position in source code for error reporting and tracing."""
    file: str
    line: int
    column: int
    offset: int  # byte offset in source

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass(frozen=True)
class Token:
    """
    A single token from the Syntecnia source.

    Every token carries its source location for full observability —
    when something goes wrong, we can trace it back to the exact character.
    """
    type: TokenType
    value: Any
    location: SourceLocation
    raw: str  # original source text that produced this token

    def __str__(self) -> str:
        if self.type in (TokenType.NEWLINE, TokenType.INDENT, TokenType.DEDENT, TokenType.EOF):
            return f"Token({self.type.name}, {self.location})"
        return f"Token({self.type.name}, {self.value!r}, {self.location})"

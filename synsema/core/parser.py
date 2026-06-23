"""
Synsema Parser — Transforms tokens into AST.

The parser implements a recursive descent parser with Pratt parsing
for expressions. Synsema's grammar is designed to be flat and readable:

    let name be "Alice"
    let age be 30

    task greet(person)
        when age of person > 18
            give "Hello, " + name of person
        otherwise
            give "Hi there, " + name of person

    each user in users
        show greet(user)

    agent Searcher
        require net("*.google.com")
        task search(query)
            let results be fetch(query)
            share results as "search_results"
"""

from typing import List, Optional, Dict
from .tokens import Token, TokenType, SourceLocation, KEYWORDS
from .lexer import Lexer, LexerError
from . import ast_nodes as ast


class ParseError(Exception):
    """Error during parsing with location info."""
    def __init__(self, message: str, location: SourceLocation):
        self.location = location
        super().__init__(f"{location}: {message}")


class Parser:
    """
    Recursive descent parser for Synsema.

    Transforms a token stream into an AST. The parser is designed
    to produce clear error messages that an agent can act on.
    """

    def __init__(self, tokens: List[Token], filename: str = "<stdin>"):
        self.tokens = tokens
        self.filename = filename
        self.pos = 0
        self._stream_depth = 0  # >0 while parsing inside a `stream` block

    def _current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]  # EOF

    def _peek(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]

    def _at_end(self) -> bool:
        return self._current().type == TokenType.EOF

    def _advance(self) -> Token:
        token = self._current()
        self.pos += 1
        return token

    def _expect(self, token_type: TokenType, message: str = "") -> Token:
        current = self._current()
        if current.type != token_type:
            msg = message or f"Expected {token_type.name}, got {current.type.name}"
            raise ParseError(msg, current.location)
        return self._advance()

    def _match(self, *types: TokenType) -> Optional[Token]:
        if self._current().type in types:
            return self._advance()
        return None

    def _check(self, *types: TokenType) -> bool:
        return self._current().type in types

    def _check_word(self, word: str) -> bool:
        """True if the current token is an identifier with this exact text.

        Used for *soft keywords* (serve, on, route, auth, requires, expect):
        words that are special only inside their construction and ordinary
        identifiers everywhere else.
        """
        tok = self._current()
        return tok.type == TokenType.IDENTIFIER and tok.value == word

    def _peek_word(self, offset: int, word: str) -> bool:
        """True if the token at `offset` is an identifier with this exact text."""
        tok = self._peek(offset)
        return tok.type == TokenType.IDENTIFIER and tok.value == word

    def _expect_word(self, word: str, message: str = "") -> Token:
        """Consume a soft keyword by its text, with a clear error otherwise."""
        if self._check_word(word):
            return self._advance()
        msg = message or f"Expected '{word}'"
        raise ParseError(msg, self._current().location)

    def _expect_name(self, what: str = "name") -> Token:
        """
        Expect an identifier to be used as a name (variable, task, param, ...).

        If the token is a reserved (hard) keyword, raise a clear error saying
        so instead of a confusing 'expected name' message.
        """
        tok = self._current()
        if tok.type == TokenType.IDENTIFIER:
            return self._advance()
        if tok.raw in KEYWORDS:
            raise ParseError(
                f"'{tok.raw}' is a reserved word in Synsema; choose another "
                f"name for the {what}",
                tok.location,
            )
        raise ParseError(f"Expected {what}, got {tok.type.name}", tok.location)

    def _skip_newlines(self):
        while self._current().type == TokenType.NEWLINE:
            self._advance()

    def _location(self) -> SourceLocation:
        return self._current().location

    # =========================================================
    # Top-level
    # =========================================================

    def parse(self) -> ast.Program:
        """Parse the full program."""
        loc = self._location()
        statements = []
        self._skip_newlines()

        while not self._at_end():
            stmt = self._parse_statement()
            if stmt is not None:
                statements.append(stmt)
            self._skip_newlines()

        return ast.Program(location=loc, statements=statements)

    # =========================================================
    # Statements
    # =========================================================

    def _parse_statement(self) -> Optional[ast.Node]:
        """Parse a single statement."""
        self._skip_newlines()
        if self._at_end():
            return None

        # Soft keywords: recognized only at the start of their construction,
        # via fixed lookahead. Everywhere else they are plain identifiers.
        if self._stream_depth > 0 and self._check_word("send"):
            return self._parse_send()
        if (self._check_word("stream")
                and self._peek(1).type == TokenType.NEWLINE
                and self._peek(2).type == TokenType.INDENT):
            return self._parse_stream()
        if self._check_word("rate_limit") and (
                self._peek(1).type == TokenType.NUMBER
                or self._peek_word(1, "none") or self._peek_word(1, "unlimited")):
            return self._parse_rate_limit()
        if self._check_word("serve") and self._peek_word(1, "on"):
            return self._parse_serve()
        if self._check_word("expect") and self._peek_word(1, "body"):
            return self._parse_expect()

        tt = self._current().type

        if tt == TokenType.LET:
            return self._parse_let()
        elif tt == TokenType.SET:
            return self._parse_set()
        elif tt == TokenType.WHEN:
            return self._parse_when()
        elif tt == TokenType.EACH:
            return self._parse_each()
        elif tt == TokenType.WHILE:
            return self._parse_while()
        elif tt == TokenType.MATCH:
            return self._parse_match()
        elif tt == TokenType.TASK:
            return self._parse_task_definition()
        elif tt == TokenType.GIVE:
            return self._parse_give()
        elif tt == TokenType.STOP:
            return self._parse_stop()
        elif tt == TokenType.AGENT:
            return self._parse_agent()
        elif tt == TokenType.SPAWN:
            return self._parse_spawn()
        elif tt == TokenType.SHARE:
            return self._parse_share()
        elif tt == TokenType.OBSERVE:
            return self._parse_observe()
        elif tt == TokenType.SIGNAL:
            return self._parse_signal()
        elif tt == TokenType.WAIT_FOR:
            return self._parse_wait_for()
        elif tt == TokenType.REQUIRE:
            return self._parse_require()
        elif tt == TokenType.SANDBOX:
            return self._parse_sandbox()
        elif tt == TokenType.INVARIANT:
            return self._parse_invariant()
        elif tt == TokenType.INTENT:
            return self._parse_intent()
        elif tt == TokenType.APPROVE:
            return self._parse_approve()
        elif tt == TokenType.SHOW:
            return self._parse_show()
        elif tt == TokenType.CONFIRM:
            return self._parse_confirm()
        elif tt == TokenType.TRACE:
            return self._parse_trace()
        elif tt == TokenType.LOG:
            return self._parse_log()
        elif tt == TokenType.MEASURE:
            return self._parse_measure()
        elif tt == TokenType.CHECKPOINT:
            return self._parse_checkpoint()
        elif tt == TokenType.TYPE:
            return self._parse_type_definition()
        elif tt == TokenType.TRY:
            return self._parse_try_recover()
        else:
            # Expression statement (e.g., function call)
            return self._parse_expression()

    def _parse_block(self) -> List[ast.Node]:
        """Parse an indented block of statements."""
        self._skip_newlines()
        self._expect(TokenType.INDENT, "Expected indented block")
        statements = []

        self._skip_newlines()
        while not self._at_end() and not self._check(TokenType.DEDENT):
            stmt = self._parse_statement()
            if stmt is not None:
                statements.append(stmt)
            self._skip_newlines()

        if self._check(TokenType.DEDENT):
            self._advance()

        return statements

    # -- let / set --

    def _parse_let(self) -> ast.LetBinding:
        """let name be expression"""
        loc = self._location()
        self._advance()  # consume 'let'
        name_tok = self._expect_name("variable after 'let'")
        self._expect(TokenType.BE, "Expected 'be' after variable name in let binding")
        value = self._parse_expression()
        return ast.LetBinding(location=loc, name=name_tok.value, value=value)

    def _parse_set(self) -> ast.SetMutation:
        """set target to expression"""
        loc = self._location()
        self._advance()  # consume 'set'
        target = self._parse_expression()
        self._expect(TokenType.TO, "Expected 'to' in set statement")
        value = self._parse_expression()
        return ast.SetMutation(location=loc, target=target, value=value)

    # -- when / otherwise --

    def _parse_when(self) -> ast.WhenStatement:
        """when condition\n    body\notherwise\n    alt"""
        loc = self._location()
        self._advance()  # consume 'when'
        condition = self._parse_expression()
        body = self._parse_block()

        otherwise = None
        otherwise_when = None

        self._skip_newlines()
        if self._match(TokenType.OTHERWISE):
            self._skip_newlines()
            if self._check(TokenType.WHEN):
                otherwise_when = self._parse_when()
            else:
                otherwise = self._parse_block()

        return ast.WhenStatement(
            location=loc,
            condition=condition,
            body=body,
            otherwise=otherwise,
            otherwise_when=otherwise_when,
        )

    # -- each --

    def _parse_each(self) -> ast.EachStatement:
        """each item in collection\n    body"""
        loc = self._location()
        self._advance()  # consume 'each'
        var_tok = self._expect_name("loop variable after 'each'")
        self._expect(TokenType.IN, "Expected 'in' after variable in each loop")
        collection = self._parse_expression()
        body = self._parse_block()
        return ast.EachStatement(
            location=loc, variable=var_tok.value,
            collection=collection, body=body,
        )

    # -- while --

    def _parse_while(self) -> ast.WhileStatement:
        loc = self._location()
        self._advance()
        condition = self._parse_expression()
        body = self._parse_block()
        return ast.WhileStatement(location=loc, condition=condition, body=body)

    # -- match --

    def _parse_match(self) -> ast.MatchStatement:
        """match value\n    is pattern\n        body"""
        loc = self._location()
        self._advance()  # consume 'match'
        value = self._parse_expression()
        self._skip_newlines()
        self._expect(TokenType.INDENT)
        arms = []

        self._skip_newlines()
        while self._check(TokenType.IS):
            arm_loc = self._location()
            self._advance()  # consume 'is'
            pattern = self._parse_expression()
            arm_body = self._parse_block()
            arms.append(ast.MatchArm(location=arm_loc, pattern=pattern, body=arm_body))
            self._skip_newlines()

        if self._check(TokenType.DEDENT):
            self._advance()

        return ast.MatchStatement(location=loc, value=value, arms=arms)

    # -- task --

    def _parse_task_definition(self) -> ast.TaskDefinition:
        """task name(params)\n    body"""
        loc = self._location()
        self._advance()  # consume 'task'
        name_tok = self._expect_name("task name")
        params = []

        if self._match(TokenType.LPAREN):
            if not self._check(TokenType.RPAREN):
                params.append(self._expect_name("parameter name").value)
                while self._match(TokenType.COMMA):
                    params.append(self._expect_name("parameter name").value)
            self._expect(TokenType.RPAREN)

        body = self._parse_block()
        return ast.TaskDefinition(
            location=loc, name=name_tok.value,
            parameters=params, body=body,
        )

    def _parse_give(self) -> ast.GiveStatement:
        loc = self._location()
        self._advance()
        value = None
        if not self._check(TokenType.NEWLINE, TokenType.DEDENT, TokenType.EOF):
            value = self._parse_expression()
        return ast.GiveStatement(location=loc, value=value)

    def _parse_stop(self) -> ast.StopStatement:
        loc = self._location()
        self._advance()
        value = None
        if not self._check(TokenType.NEWLINE, TokenType.DEDENT, TokenType.EOF):
            value = self._parse_expression()
        return ast.StopStatement(location=loc, value=value)

    # -- type --

    def _parse_type_definition(self) -> ast.TypeDefinition:
        """type Name\n    field: type"""
        loc = self._location()
        self._advance()  # consume 'type'
        name_tok = self._expect_name("type name")
        self._skip_newlines()
        self._expect(TokenType.INDENT)
        fields = []

        self._skip_newlines()
        while not self._check(TokenType.DEDENT, TokenType.EOF):
            field_name = self._expect_name("field name").value
            self._expect(TokenType.COLON)
            type_name = self._expect(TokenType.IDENTIFIER).value
            fields.append((field_name, type_name))
            self._skip_newlines()

        if self._check(TokenType.DEDENT):
            self._advance()

        return ast.TypeDefinition(location=loc, name=name_tok.value, fields=fields)

    # -- try/recover --

    def _parse_try_recover(self) -> ast.TryRecover:
        """try\n    body\nrecover error_var\n    recover_body"""
        loc = self._location()
        self._advance()  # consume 'try'
        try_body = self._parse_block()

        self._skip_newlines()
        self._expect(TokenType.RECOVER, "Expected 'recover' after try block")

        # Optional error variable name
        error_var = "error"
        if self._check(TokenType.IDENTIFIER):
            error_var = self._advance().value

        recover_body = self._parse_block()

        return ast.TryRecover(
            location=loc,
            try_body=try_body,
            error_variable=error_var,
            recover_body=recover_body,
        )

    # -- agent --

    def _parse_agent(self) -> ast.AgentDefinition:
        """agent Name\n    body"""
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.IDENTIFIER)
        body = self._parse_block()
        return ast.AgentDefinition(location=loc, name=name_tok.value, body=body)

    def _parse_spawn(self) -> ast.SpawnStatement:
        """spawn AgentName with key = value"""
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.IDENTIFIER)
        args = {}
        if self._match(TokenType.WITH):
            key = self._expect(TokenType.IDENTIFIER).value
            self._expect(TokenType.ASSIGN)
            value = self._parse_expression()
            args[key] = value
            while self._match(TokenType.COMMA):
                key = self._expect(TokenType.IDENTIFIER).value
                self._expect(TokenType.ASSIGN)
                value = self._parse_expression()
                args[key] = value
        return ast.SpawnStatement(location=loc, agent_name=name_tok.value, arguments=args)

    def _parse_share(self) -> ast.ShareStatement:
        """share value as key_expression"""
        loc = self._location()
        self._advance()
        value = self._parse_expression()
        self._expect(TokenType.AS)
        key_expr = self._parse_expression()
        return ast.ShareStatement(location=loc, value=value, key=key_expr)

    def _parse_observe(self) -> ast.ObserveStatement:
        """observe key_expression as variable"""
        loc = self._location()
        self._advance()
        key_expr = self._parse_expression()
        self._expect(TokenType.AS)
        var_tok = self._expect(TokenType.IDENTIFIER)
        return ast.ObserveStatement(location=loc, key=key_expr, variable=var_tok.value)

    def _parse_signal(self) -> ast.SignalStatement:
        """signal "done" """
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.TEXT)
        data = None
        if self._match(TokenType.WITH):
            data = self._parse_expression()
        return ast.SignalStatement(location=loc, name=name_tok.value, data=data)

    def _parse_wait_for(self) -> ast.WaitForStatement:
        """wait_for "done" as result"""
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.TEXT)
        variable = None
        if self._match(TokenType.AS):
            variable = self._expect(TokenType.IDENTIFIER).value
        return ast.WaitForStatement(location=loc, signal_name=name_tok.value, variable=variable)

    # -- capabilities --

    def _parse_require(self) -> ast.RequireStatement:
        """require net("api.example.com")"""
        loc = self._location()
        self._advance()
        cap_tok = self._expect(TokenType.IDENTIFIER)
        scope = None
        if self._match(TokenType.LPAREN):
            scope = self._parse_expression()
            self._expect(TokenType.RPAREN)
        return ast.RequireStatement(location=loc, capability=cap_tok.value, scope=scope)

    def _parse_sandbox(self) -> ast.SandboxBlock:
        """sandbox\n    body"""
        loc = self._location()
        self._advance()
        body = self._parse_block()
        return ast.SandboxBlock(location=loc, body=body)

    def _parse_invariant(self) -> ast.InvariantDeclaration:
        """invariant: condition"""
        loc = self._location()
        self._advance()
        self._expect(TokenType.COLON)
        condition = self._parse_expression()
        return ast.InvariantDeclaration(location=loc, condition=condition)

    def _parse_intent(self) -> ast.IntentDeclaration:
        """intent: "description" """
        loc = self._location()
        self._advance()
        self._expect(TokenType.COLON)
        desc_tok = self._expect(TokenType.TEXT)
        return ast.IntentDeclaration(location=loc, description=desc_tok.value)

    # -- human interaction --

    def _parse_approve(self) -> ast.ApproveStatement:
        """approve "message" """
        loc = self._location()
        self._advance()
        message = self._parse_expression()
        return ast.ApproveStatement(location=loc, message=message)

    def _parse_show(self) -> ast.ShowStatement:
        """show expression"""
        loc = self._location()
        self._advance()
        value = self._parse_expression()
        label = None
        if self._match(TokenType.AS):
            label = self._expect(TokenType.TEXT).value
        return ast.ShowStatement(location=loc, value=value, label=label)

    def _parse_confirm(self) -> ast.ConfirmStatement:
        """confirm "message" """
        loc = self._location()
        self._advance()
        message = self._parse_expression()
        return ast.ConfirmStatement(location=loc, message=message)

    # -- observability --

    def _parse_trace(self) -> ast.TraceBlock:
        """trace "name"\n    body"""
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.TEXT)
        body = self._parse_block()
        return ast.TraceBlock(location=loc, name=name_tok.value, body=body)

    def _parse_log(self) -> ast.LogStatement:
        """log "message" """
        loc = self._location()
        self._advance()
        message = self._parse_expression()
        return ast.LogStatement(location=loc, message=message)

    def _parse_measure(self) -> ast.MeasureBlock:
        """measure "name"\n    body"""
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.TEXT)
        body = self._parse_block()
        return ast.MeasureBlock(location=loc, name=name_tok.value, body=body)

    def _parse_checkpoint(self) -> ast.CheckpointStatement:
        """checkpoint "name" """
        loc = self._location()
        self._advance()
        name_tok = self._expect(TokenType.TEXT)
        return ast.CheckpointStatement(location=loc, name=name_tok.value)

    # -- HTTP server --

    def _parse_serve(self) -> ast.ServeBlock:
        """
        serve on PORT
            auth with <task>          (optional)
            route "GET /path" [requires auth]
                body...
        """
        loc = self._location()
        self._advance()  # consume soft keyword 'serve'
        self._expect_word("on", "Expected 'on' after 'serve' (serve on PORT)")
        port = self._parse_expression()

        auth_handler = None
        max_body = None
        max_streams = None
        rate_limit = None
        static_mounts = []
        cors = None
        describe = None
        private = False
        routes = []

        self._skip_newlines()
        self._expect(TokenType.INDENT, "Expected an indented block after 'serve on PORT'")
        self._skip_newlines()

        while not self._at_end() and not self._check(TokenType.DEDENT):
            if self._check_word("auth"):
                self._advance()  # consume soft keyword 'auth'
                self._expect(TokenType.WITH, "Expected 'with' after 'auth' (auth with <task>)")
                auth_handler = self._parse_expression()
            elif self._check_word("max_body"):
                self._advance()  # consume soft keyword 'max_body'
                max_body = self._parse_expression()
            elif self._check_word("max_streams"):
                self._advance()  # consume soft keyword 'max_streams'
                max_streams = self._parse_expression()
            elif self._check_word("rate_limit"):
                rate_limit = self._parse_rate_limit()
            elif self._check_word("static"):
                self._advance()  # consume soft keyword 'static'
                first = self._parse_expression()
                if self._check_word("from"):
                    self._advance()  # consume soft keyword 'from'
                    directory = self._parse_expression()
                    static_mounts.append(ast.StaticMount(
                        location=loc, prefix=first, directory=directory))
                else:
                    static_mounts.append(ast.StaticMount(
                        location=loc, prefix=None, directory=first))
            elif self._check_word("cors"):
                self._advance()  # consume soft keyword 'cors'
                cors = self._parse_expression()
            elif self._check_word("describe"):
                describe = self._parse_describe()
            elif self._check_word("private"):
                self._advance()  # consume soft keyword 'private'
                private = True
            elif self._check_word("route"):
                routes.append(self._parse_route())
            else:
                tok = self._current()
                raise ParseError(
                    f"Inside 'serve', expected 'auth with ...', 'route ...', "
                    f"'static ...', 'cors ...', 'describe' or 'private', "
                    f"got {tok.type.name}",
                    tok.location,
                )
            self._skip_newlines()

        if self._check(TokenType.DEDENT):
            self._advance()

        # A route that 'requires auth' needs an 'auth with <task>' on the block.
        if auth_handler is None:
            for r in routes:
                if r.requires_auth:
                    raise ParseError(
                        f"route \"{r.method} {r.path}\" uses 'requires auth' but the "
                        f"'serve' block declares no 'auth with <task>'",
                        r.location,
                    )

        return ast.ServeBlock(
            location=loc, port=port, auth_handler=auth_handler,
            max_body=max_body, max_streams=max_streams,
            rate_limit=rate_limit, static_mounts=static_mounts, cors=cors,
            describe=describe, private=private, routes=routes,
        )

    def _parse_describe(self) -> ast.DescribeClause:
        """
        describe
            about: "..."
            api: ["...", "..."]
        """
        loc = self._location()
        self._advance()  # consume soft keyword 'describe'
        about = None
        api = None
        self._skip_newlines()
        self._expect(TokenType.INDENT, "Expected an indented block after 'describe'")
        self._skip_newlines()
        while not self._at_end() and not self._check(TokenType.DEDENT):
            if self._check_word("about"):
                self._advance()
                self._expect(TokenType.COLON, "Expected ':' after 'about'")
                about = self._parse_expression()
            elif self._check_word("api"):
                self._advance()
                self._expect(TokenType.COLON, "Expected ':' after 'api'")
                api = self._parse_expression()
            else:
                tok = self._current()
                raise ParseError(
                    f"Inside 'describe', expected 'about:' or 'api:', got {tok.type.name}",
                    tok.location,
                )
            self._skip_newlines()
        if self._check(TokenType.DEDENT):
            self._advance()
        return ast.DescribeClause(location=loc, about=about, api=api)

    def _parse_route(self) -> ast.RouteDefinition:
        """route "METHOD /path/:param" [requires auth]\n    body"""
        loc = self._location()
        self._advance()  # consume soft keyword 'route'
        spec_tok = self._expect(TokenType.TEXT, "Expected a route spec string, e.g. \"GET /path\"")
        method, path, param_names = self._split_route_spec(spec_tok.value, spec_tok.location)

        requires_auth = False
        if self._check_word("requires"):
            self._advance()  # consume soft keyword 'requires'
            self._expect_word("auth", "Expected 'auth' after 'requires' (requires auth)")
            requires_auth = True

        body = self._parse_block()
        # A `rate_limit` declared inside the route body is a route-level override.
        rate_limit = None
        clean_body = []
        for s in body:
            if isinstance(s, ast.RateLimitClause):
                rate_limit = s
            else:
                clean_body.append(s)
        body = clean_body
        streaming = any(isinstance(s, ast.StreamBlock) for s in body)
        return ast.RouteDefinition(
            location=loc, method=method, path=path,
            param_names=param_names, requires_auth=requires_auth,
            streaming=streaming, rate_limit=rate_limit, body=body,
        )

    def _parse_rate_limit(self) -> ast.RateLimitClause:
        """rate_limit N per <second|minute|hour>  |  rate_limit none|unlimited"""
        loc = self._location()
        self._advance()  # consume soft keyword 'rate_limit'
        if self._check_word("none") or self._check_word("unlimited"):
            self._advance()
            return ast.RateLimitClause(location=loc, unlimited=True)
        count = self._parse_expression()
        self._expect_word("per", "Expected 'per' in rate_limit (e.g. rate_limit 100 per minute)")
        window_tok = self._expect(TokenType.IDENTIFIER, "Expected a window: second, minute, or hour")
        window = window_tok.value
        if window not in ("second", "minute", "hour"):
            raise ParseError(
                f"rate_limit window must be second, minute, or hour, got {window!r}",
                window_tok.location,
            )
        return ast.RateLimitClause(location=loc, count=count, window=window)

    def _parse_stream(self) -> ast.StreamBlock:
        """stream\n    send ...  — an SSE response block."""
        loc = self._location()
        self._advance()  # consume soft keyword 'stream'
        self._stream_depth += 1
        try:
            body = self._parse_block()
        finally:
            self._stream_depth -= 1
        return ast.StreamBlock(location=loc, body=body)

    def _parse_send(self) -> ast.SendStatement:
        """send <value> [as "event"]"""
        loc = self._location()
        self._advance()  # consume soft keyword 'send'
        value = self._parse_expression()
        event_name = None
        if self._match(TokenType.AS):
            ev_tok = self._expect(TokenType.TEXT, "Expected an event name string after 'as'")
            event_name = ev_tok.value
        return ast.SendStatement(location=loc, value=value, event_name=event_name)

    def _split_route_spec(self, spec: str, loc) -> tuple:
        """
        Parse 'GET /products/:id' → ('GET', '/products/:id', ['id']).

        Supports a single trailing catch-all segment: 'GET /files/*path' captures
        the rest of the path (variable depth) as `params.path`.
        """
        parts = spec.strip().split(None, 1)
        if len(parts) != 2:
            raise ParseError(
                f"Route spec must be \"METHOD /path\", got {spec!r}", loc,
            )
        method = parts[0].upper()
        path = parts[1].strip()
        if not path.startswith("/"):
            raise ParseError(f"Route path must start with '/', got {path!r}", loc)
        segs = [s for s in path.split("/") if s != ""]
        param_names = []
        for i, seg in enumerate(segs):
            if seg.startswith(":") and len(seg) > 1:
                param_names.append(seg[1:])
            elif seg.startswith("*"):
                if len(seg) == 1:
                    raise ParseError(
                        f"Catch-all segment must be named, e.g. '*path', got {seg!r}", loc)
                if i != len(segs) - 1:
                    raise ParseError(
                        f"Catch-all '*{seg[1:]}' must be the LAST segment of the path, "
                        f"got {path!r}", loc)
                param_names.append(seg[1:])
        return method, path, param_names

    def _parse_expect(self) -> ast.ExpectStatement:
        """expect body {field: type, ...}"""
        loc = self._location()
        self._advance()  # consume soft keyword 'expect'
        target_tok = self._expect_word("body", "Expected 'body' after 'expect'")
        self._expect(TokenType.LBRACE, "Expected '{' to declare the expected shape")
        shape = []
        if not self._check(TokenType.RBRACE):
            shape.append(self._parse_expect_field())
            while self._match(TokenType.COMMA):
                if self._check(TokenType.RBRACE):
                    break
                shape.append(self._parse_expect_field())
        self._expect(TokenType.RBRACE, "Expected '}' to close the expected shape")
        return ast.ExpectStatement(location=loc, target=target_tok.value, shape=shape)

    def _parse_expect_field(self) -> tuple:
        field_tok = self._expect(TokenType.IDENTIFIER, "Expected a field name in expect shape")
        self._expect(TokenType.COLON, "Expected ':' after field name in expect shape")
        type_tok = self._expect(TokenType.IDENTIFIER, "Expected a type name (text, number, bool, list, map)")
        return (field_tok.value, type_tok.value)

    # =========================================================
    # Expressions (Pratt parser)
    # =========================================================

    def _parse_expression(self) -> ast.Node:
        """Parse an expression using precedence climbing."""
        return self._parse_or()

    def _parse_or(self) -> ast.Node:
        left = self._parse_and()
        while self._check(TokenType.OR):
            op = self._advance()
            right = self._parse_and()
            left = ast.BinaryOp(location=op.location, left=left, operator="or", right=right)
        return left

    def _parse_and(self) -> ast.Node:
        left = self._parse_not()
        while self._check(TokenType.AND):
            op = self._advance()
            right = self._parse_not()
            left = ast.BinaryOp(location=op.location, left=left, operator="and", right=right)
        return left

    def _parse_not(self) -> ast.Node:
        if self._check(TokenType.NOT):
            op = self._advance()
            operand = self._parse_not()
            return ast.UnaryOp(location=op.location, operator="not", operand=operand)
        return self._parse_comparison()

    def _parse_comparison(self) -> ast.Node:
        left = self._parse_addition()
        while self._check(TokenType.EQUAL, TokenType.NOT_EQUAL,
                          TokenType.LESS, TokenType.GREATER,
                          TokenType.LESS_EQUAL, TokenType.GREATER_EQUAL):
            op = self._advance()
            right = self._parse_addition()
            left = ast.BinaryOp(location=op.location, left=left, operator=op.value, right=right)
        return left

    def _parse_addition(self) -> ast.Node:
        left = self._parse_multiplication()
        while self._check(TokenType.PLUS, TokenType.MINUS):
            op = self._advance()
            right = self._parse_multiplication()
            left = ast.BinaryOp(location=op.location, left=left, operator=op.value, right=right)
        return left

    def _parse_multiplication(self) -> ast.Node:
        left = self._parse_power()
        while self._check(TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            op = self._advance()
            right = self._parse_power()
            left = ast.BinaryOp(location=op.location, left=left, operator=op.value, right=right)
        return left

    def _parse_power(self) -> ast.Node:
        left = self._parse_unary()
        if self._check(TokenType.POWER):
            op = self._advance()
            right = self._parse_power()  # right-associative
            left = ast.BinaryOp(location=op.location, left=left, operator="**", right=right)
        return left

    def _parse_unary(self) -> ast.Node:
        if self._check(TokenType.MINUS):
            op = self._advance()
            operand = self._parse_unary()
            return ast.UnaryOp(location=op.location, operator="-", operand=operand)
        return self._parse_pipe()

    def _parse_pipe(self) -> ast.Node:
        """x |> transform |> another"""
        left = self._parse_postfix()
        if self._check(TokenType.PIPE):
            loc = self._location()
            transforms = []
            while self._match(TokenType.PIPE):
                transforms.append(self._parse_postfix())
            return ast.PipeExpression(location=loc, value=left, transforms=transforms)
        return left

    def _parse_postfix(self) -> ast.Node:
        """Handle function calls, property access, indexing."""
        node = self._parse_primary()

        while True:
            if self._check(TokenType.LPAREN):
                # Function call
                loc = self._location()
                self._advance()
                args = []
                if not self._check(TokenType.RPAREN):
                    args.append(self._parse_expression())
                    while self._match(TokenType.COMMA):
                        args.append(self._parse_expression())
                self._expect(TokenType.RPAREN)
                node = ast.TaskCall(location=loc, name=node, arguments=args)
            elif self._check(TokenType.DOT):
                loc = self._location()
                self._advance()
                prop = self._expect(TokenType.IDENTIFIER)
                node = ast.PropertyAccess(
                    location=loc, property_name=prop.value, object=node,
                )
            elif self._check(TokenType.LBRACKET):
                loc = self._location()
                self._advance()
                index = self._parse_expression()
                self._expect(TokenType.RBRACKET)
                node = ast.IndexAccess(location=loc, object=node, index=index)
            elif self._check(TokenType.OF):
                # "name of person" syntax → PropertyAccess
                loc = self._location()
                self._advance()
                obj = self._parse_postfix()
                node = ast.PropertyAccess(
                    location=loc, property_name=node.name if isinstance(node, ast.Identifier) else str(node),
                    object=obj,
                )
            else:
                break

        return node

    def _is_lambda_ahead(self) -> bool:
        """At a '(', report whether its matching ')' is immediately followed by '=>'.

        Bounded lookahead that consumes nothing — only paren depth is tracked,
        so the disambiguation works regardless of what sits inside the parens.
        A '(' whose match is followed by '=>' begins a lambda param list;
        anything else (e.g. (1 + 2) * 3) is an ordinary grouped expression.
        """
        depth = 0
        i = self.pos
        n = len(self.tokens)
        while i < n:
            t = self.tokens[i].type
            if t == TokenType.LPAREN:
                depth += 1
            elif t == TokenType.RPAREN:
                depth -= 1
                if depth == 0:
                    nxt = i + 1
                    return nxt < n and self.tokens[nxt].type == TokenType.FAT_ARROW
            elif t == TokenType.EOF:
                break
            i += 1
        return False

    def _parse_lambda(self) -> ast.LambdaExpression:
        """(params) => expr — anonymous single-expression function.

        Params are zero or more identifiers (parens always required), mirroring
        a task's param list. The body is a single full-precedence expression.
        """
        loc = self._location()
        self._expect(TokenType.LPAREN)
        params = []
        if not self._check(TokenType.RPAREN):
            params.append(self._expect_name("lambda parameter").value)
            while self._match(TokenType.COMMA):
                params.append(self._expect_name("lambda parameter").value)
        self._expect(TokenType.RPAREN)
        self._expect(TokenType.FAT_ARROW)
        body = self._parse_expression()
        return ast.LambdaExpression(location=loc, parameters=params, body=body)

    def _desugar_template(self, segments, loc) -> ast.Node:
        """Desugar a backtick template into a left-assoc `+` chain (§5).

        literal segment → TextLiteral; interpolation segment → its parsed
        expression. The first operand is forced to be a TextLiteral (use "")
        so the whole template always evaluates to text via the Text-coercing
        `+`. A pure-literal template → a single TextLiteral; empty → "".
        The AST and interpreter are untouched (TextLiteral + BinaryOp only).
        """
        node = None
        for seg in segments:
            if seg[0] == "lit":
                part = ast.TextLiteral(location=loc, value=seg[1])
            else:  # ("expr", src, interp_loc)
                _, src, interp_loc = seg
                part = self._parse_interp_expression(src, interp_loc)
            if node is None:
                if isinstance(part, ast.TextLiteral):
                    node = part
                else:
                    node = ast.BinaryOp(
                        location=loc,
                        left=ast.TextLiteral(location=loc, value=""),
                        operator="+", right=part,
                    )
            else:
                node = ast.BinaryOp(location=loc, left=node, operator="+", right=part)
        if node is None:
            node = ast.TextLiteral(location=loc, value="")
        return node

    def _parse_interp_expression(self, src: str, loc) -> ast.Node:
        """Parse one `{…}` interpolation hole's source as a single expression.

        Mirrors Rust `parse_expression_source`: lex + parse ONE expression with
        no leftover-token check. The hole source is trimmed first (same as the
        SSR template `{ expr }` convention) so surrounding whitespace doesn't
        get lexed as indentation. A lexer error is converted to a ParseError so
        both implementations report it in the same category (parity gate).
        """
        try:
            sub_tokens = Lexer(src.strip(), self.filename).tokenize_filtered()
        except LexerError as e:
            raise ParseError(e.message, e.location)
        sub_parser = Parser(sub_tokens, self.filename)
        return sub_parser._parse_expression()

    def _parse_primary(self) -> ast.Node:
        """Parse primary expressions (literals, identifiers, grouped, etc.)."""
        loc = self._location()
        tok = self._current()

        if tok.type == TokenType.NUMBER:
            self._advance()
            return ast.NumberLiteral(location=loc, value=tok.value)

        if tok.type == TokenType.TEXT:
            self._advance()
            return ast.TextLiteral(location=loc, value=tok.value)

        if tok.type == TokenType.TEMPLATE:
            self._advance()
            return self._desugar_template(tok.value, loc)

        if tok.type == TokenType.BOOL_TRUE:
            self._advance()
            return ast.BoolLiteral(location=loc, value=True)

        if tok.type == TokenType.BOOL_FALSE:
            self._advance()
            return ast.BoolLiteral(location=loc, value=False)

        if tok.type == TokenType.NOTHING:
            self._advance()
            return ast.NothingLiteral(location=loc)

        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return ast.Identifier(location=loc, name=tok.value)

        # List literal: [1, 2, 3]
        if tok.type == TokenType.LBRACKET:
            self._advance()
            elements = []
            if not self._check(TokenType.RBRACKET):
                elements.append(self._parse_expression())
                while self._match(TokenType.COMMA):
                    if self._check(TokenType.RBRACKET):
                        break  # trailing comma
                    elements.append(self._parse_expression())
            self._expect(TokenType.RBRACKET)
            return ast.ListLiteral(location=loc, elements=elements)

        # Map literal: {"key": value}
        if tok.type == TokenType.LBRACE:
            self._advance()
            pairs = []
            if not self._check(TokenType.RBRACE):
                key = self._parse_expression()
                self._expect(TokenType.COLON)
                val = self._parse_expression()
                pairs.append((key, val))
                while self._match(TokenType.COMMA):
                    if self._check(TokenType.RBRACE):
                        break
                    key = self._parse_expression()
                    self._expect(TokenType.COLON)
                    val = self._parse_expression()
                    pairs.append((key, val))
            self._expect(TokenType.RBRACE)
            return ast.MapLiteral(location=loc, pairs=pairs)

        # Lambda — (params) => expr — or grouped expression — (expr)
        if tok.type == TokenType.LPAREN:
            if self._is_lambda_ahead():
                return self._parse_lambda()
            self._advance()
            expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return expr

        # LLM expressions
        if tok.type == TokenType.REASON:
            return self._parse_reason_expr()
        if tok.type == TokenType.DECIDE:
            return self._parse_decide_expr()
        if tok.type == TokenType.ANALYZE:
            return self._parse_analyze_expr()
        if tok.type == TokenType.GENERATE:
            return self._parse_generate_expr()
        if tok.type == TokenType.ASK:
            return self._parse_ask_expr()

        # Human interaction as expressions (for: let x be approve "...")
        if tok.type == TokenType.APPROVE:
            return self._parse_approve()
        if tok.type == TokenType.CONFIRM:
            return self._parse_confirm()
        if tok.type == TokenType.SHOW:
            return self._parse_show()

        raise ParseError(f"Unexpected token: {tok.type.name} ({tok.value!r})", loc)

    # -- LLM expression parsers --

    def _parse_reason_expr(self) -> ast.ReasonExpression:
        loc = self._location()
        self._advance()  # consume 'reason'
        # reason about subject
        subject = None
        if self._current().value == "about":
            self._advance()
            subject = self._parse_expression()
        context = {}
        if self._match(TokenType.WITH):
            key = self._expect(TokenType.IDENTIFIER).value
            self._expect(TokenType.ASSIGN)
            val = self._parse_expression()
            context[key] = val
        body = []
        if self._check(TokenType.NEWLINE) and self._peek().type == TokenType.INDENT:
            body = self._parse_block()
        return ast.ReasonExpression(location=loc, subject=subject, context=context, body=body)

    def _parse_decide_expr(self) -> ast.DecideExpression:
        loc = self._location()
        self._advance()  # consume 'decide'
        # decide between [...] given data
        options = None
        if self._current().value == "between":
            self._advance()
            options = self._parse_expression()
        given = None
        if self._current().value == "given":
            self._advance()
            given = self._parse_expression()
        return ast.DecideExpression(location=loc, options=options, given=given)

    def _parse_analyze_expr(self) -> ast.AnalyzeExpression:
        loc = self._location()
        self._advance()
        data = self._parse_expression()
        objective = ""
        if self._current().value == "for":
            self._advance()
            obj_tok = self._expect(TokenType.TEXT)
            objective = obj_tok.value
        return ast.AnalyzeExpression(location=loc, data=data, objective=objective)

    def _parse_generate_expr(self) -> ast.GenerateExpression:
        loc = self._location()
        self._advance()
        target_tok = self._expect(TokenType.TEXT)
        given = None
        if self._current().value == "given":
            self._advance()
            given = self._parse_expression()
        params = {}
        if self._match(TokenType.WITH):
            key = self._expect(TokenType.IDENTIFIER).value
            self._expect(TokenType.ASSIGN)
            val = self._parse_expression()
            params[key] = val
        return ast.GenerateExpression(
            location=loc, target=target_tok.value, given=given, parameters=params,
        )

    def _parse_ask_expr(self) -> ast.AskExpression:
        loc = self._location()
        self._advance()
        prompt = self._parse_expression()
        options = None
        if self._match(TokenType.WITH):
            options = self._parse_expression()
        return ast.AskExpression(location=loc, prompt=prompt, options=options)


def parse(source: str, filename: str = "<stdin>") -> ast.Program:
    """Convenience function: source code → AST."""
    lexer = Lexer(source, filename)
    tokens = lexer.tokenize_filtered()
    parser = Parser(tokens, filename)
    return parser.parse()

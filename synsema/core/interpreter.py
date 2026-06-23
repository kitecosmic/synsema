"""
Synsema Interpreter — Evaluates the AST.

The interpreter walks the AST and executes each node. Key features:
- Every operation is traceable (origin tracking)
- Capability checking before side effects
- Human interaction points pause execution
- LLM integration for reasoning/decide/analyze/generate
- Full state inspection at any point
"""

from typing import Any, Dict, List, Optional, Callable
from . import ast_nodes as ast
from .types import (
    SynValue, SynTaskValue, BuiltinTask,
    syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map, syn_task,
    SynNumber, SynText, SynBool, SynList, SynMap, SynNothing, SynTask,
)
from .tokens import SourceLocation


class RuntimeError(Exception):
    """Runtime error with location."""
    def __init__(self, message: str, location: Optional[SourceLocation] = None):
        self.location = location
        loc_str = f"{location}: " if location else ""
        super().__init__(f"{loc_str}{message}")


class GiveSignal(Exception):
    """Used to implement 'give' (return) via exception unwinding."""
    def __init__(self, value: SynValue):
        self.value = value


class StopSignal(Exception):
    """Used to implement 'stop' (break) via exception unwinding."""
    def __init__(self, value: Optional[SynValue] = None):
        self.value = value


class ApprovalRequired(Exception):
    """Raised when human approval is needed."""
    def __init__(self, message: str, context: Any = None):
        self.message = message
        self.context = context
        super().__init__(f"Approval required: {message}")


class ExpectViolation(Exception):
    """
    Raised when an `expect body {...}` validation fails inside an HTTP handler.
    The serve runtime catches this and returns a 400 response with `field`
    naming the offending field. It is NOT a server crash.
    """
    def __init__(self, message: str, field: str = "", expected: str = ""):
        self.field = field
        self.expected = expected
        super().__init__(message)


class Environment:
    """
    Variable scope with parent chain.

    Each environment knows its parent, enabling lexical scoping.
    The full chain is inspectable for debugging.
    """
    def __init__(self, parent: Optional['Environment'] = None, name: str = ""):
        self.parent = parent
        self.name = name
        self.bindings: Dict[str, SynValue] = {}

    def get(self, name: str) -> SynValue:
        if name in self.bindings:
            return self.bindings[name]
        if self.parent:
            return self.parent.get(name)
        raise RuntimeError(f"Undefined variable: '{name}'")

    def set(self, name: str, value: SynValue):
        """Set a variable in the current scope."""
        self.bindings[name] = value

    def update(self, name: str, value: SynValue):
        """Update an existing variable in any scope."""
        if name in self.bindings:
            self.bindings[name] = value
            return
        if self.parent:
            self.parent.update(name, value)
            return
        raise RuntimeError(f"Cannot set undefined variable: '{name}'. Use 'let' first.")

    def dump(self) -> Dict[str, SynValue]:
        """Dump all visible bindings (for observability)."""
        result = {}
        if self.parent:
            result.update(self.parent.dump())
        result.update(self.bindings)
        return result


class TraceEntry:
    """A single entry in the execution trace."""
    def __init__(self, name: str, location: SourceLocation, data: Dict = None):
        self.name = name
        self.location = location
        self.data = data or {}
        self.children: List['TraceEntry'] = []
        self.result: Optional[SynValue] = None
        self.duration_ms: Optional[float] = None


class Interpreter:
    """
    Evaluates Synsema AST nodes.

    The interpreter maintains:
    - Environment chain (variable scopes)
    - Execution trace (full history of operations)
    - Capability set (what operations are allowed)
    - Blackboard (shared state for agents)
    - Human interaction callback
    - LLM callback for reasoning operations
    """

    def __init__(self):
        self.global_env = Environment(name="global")
        self.trace: List[TraceEntry] = []
        self.capabilities: set = set()
        self.blackboard: Dict[str, SynValue] = {}
        self.logs: List[Dict] = []

        # Callbacks (pluggable)
        self.human_callback: Optional[Callable] = None
        self.llm_callback: Optional[Callable] = None
        self.output_callback: Optional[Callable] = None

        # Intent enforcement
        self.intent_enforcer = None  # set by engine
        self._intent_frozen = False

        # SSE streaming sink (set by the server for streaming routes)
        self._stream_emit = None

        self._register_builtins()
        self._register_intentional_ops()

    def _register_builtins(self):
        """Register built-in tasks."""
        builtins = {
            "print": BuiltinTask("print", self._builtin_print),
            "length": BuiltinTask("length", self._builtin_length, 1),
            "text": BuiltinTask("text", self._builtin_to_text, 1),
            "number": BuiltinTask("number", self._builtin_to_number, 1),
            "append": BuiltinTask("append", self._builtin_append, 2),
            "keys": BuiltinTask("keys", self._builtin_keys, 1),
            "values": BuiltinTask("values", self._builtin_values, 1),
            "contains": BuiltinTask("contains", self._builtin_contains, 2),
            "split": BuiltinTask("split", self._builtin_split, 2),
            "join": BuiltinTask("join", self._builtin_join, 2),
            "range": BuiltinTask("range", self._builtin_range),
            "type_of": BuiltinTask("type_of", self._builtin_type_of, 1),
            "slice": BuiltinTask("slice", self._builtin_slice),
            "fmt": BuiltinTask("fmt", self._builtin_fmt, 1),
            "upper": BuiltinTask("upper", self._builtin_upper, 1),
            "lower": BuiltinTask("lower", self._builtin_lower, 1),
            "trim": BuiltinTask("trim", self._builtin_trim, 1),
            "starts_with": BuiltinTask("starts_with", self._builtin_starts_with, 2),
            "ends_with": BuiltinTask("ends_with", self._builtin_ends_with, 2),
            "replace_text": BuiltinTask("replace_text", self._builtin_replace_text, 3),
            # Regex (pure computation — no capability required)
            "matches": BuiltinTask("matches", self._builtin_matches, 2),
            "find_all": BuiltinTask("find_all", self._builtin_find_all, 2),
            "capture": BuiltinTask("capture", self._builtin_capture, 2),
            "replace_re": BuiltinTask("replace_re", self._builtin_replace_re, 3),
            # SSR templates — render("page.html", data) → text/html (auto-escaped)
            "render": BuiltinTask("render", self._builtin_render, -1),
        }
        for name, builtin in builtins.items():
            self.global_env.set(name, SynValue(raw=builtin, type=SynTask()))

    def _register_intentional_ops(self):
        """Register intentional operations (apply, where, transform, etc.)."""
        from .intentional_ops import register_intentional_builtins
        register_intentional_builtins(self.global_env, self)

    # -- Builtins --

    def _builtin_print(self, args: List[SynValue]) -> SynValue:
        text = " ".join(str(a) for a in args)
        if self.output_callback:
            self.output_callback(text)
        else:
            print(text)
        return syn_nothing()

    def _builtin_length(self, args: List[SynValue]) -> SynValue:
        val = args[0]
        if isinstance(val.type, (SynText, SynList)):
            return syn_number(len(val.raw))
        if isinstance(val.type, SynMap):
            return syn_number(len(val.raw))
        raise RuntimeError(f"Cannot get length of {val.type.name}")

    def _builtin_to_text(self, args: List[SynValue]) -> SynValue:
        return syn_text(str(args[0]))

    def _builtin_to_number(self, args: List[SynValue]) -> SynValue:
        try:
            return syn_number(float(args[0].raw))
        except (ValueError, TypeError):
            raise RuntimeError(f"Cannot convert {args[0]} to number")

    def _builtin_append(self, args: List[SynValue]) -> SynValue:
        lst, item = args[0], args[1]
        if not isinstance(lst.type, SynList):
            raise RuntimeError("First argument to append must be a list")
        new_list = lst.raw + [item]
        return syn_list(new_list)

    def _builtin_keys(self, args: List[SynValue]) -> SynValue:
        m = args[0]
        if not isinstance(m.type, SynMap):
            raise RuntimeError("keys() requires a map")
        return syn_list([syn_text(k) for k in m.raw.keys()])

    def _builtin_values(self, args: List[SynValue]) -> SynValue:
        m = args[0]
        if not isinstance(m.type, SynMap):
            raise RuntimeError("values() requires a map")
        return syn_list(list(m.raw.values()))

    def _builtin_contains(self, args: List[SynValue]) -> SynValue:
        collection, item = args[0], args[1]
        if isinstance(collection.type, SynList):
            for elem in collection.raw:
                if elem.raw == item.raw:
                    return syn_bool(True)
            return syn_bool(False)
        if isinstance(collection.type, SynText):
            return syn_bool(str(item.raw) in collection.raw)
        if isinstance(collection.type, SynMap):
            return syn_bool(str(item.raw) in collection.raw)
        raise RuntimeError(f"Cannot check containment in {collection.type.name}")

    def _builtin_split(self, args: List[SynValue]) -> SynValue:
        text, sep = args[0], args[1]
        parts = str(text.raw).split(str(sep.raw))
        return syn_list([syn_text(p) for p in parts])

    def _builtin_join(self, args: List[SynValue]) -> SynValue:
        lst, sep = args[0], args[1]
        if not isinstance(lst.type, SynList):
            raise RuntimeError("First argument to join must be a list")
        return syn_text(str(sep.raw).join(str(item) for item in lst.raw))

    def _builtin_range(self, args: List[SynValue]) -> SynValue:
        if len(args) == 1:
            return syn_list([syn_number(i) for i in range(int(args[0].raw))])
        elif len(args) == 2:
            return syn_list([syn_number(i) for i in range(int(args[0].raw), int(args[1].raw))])
        elif len(args) == 3:
            return syn_list([syn_number(i) for i in range(int(args[0].raw), int(args[1].raw), int(args[2].raw))])
        raise RuntimeError("range() takes 1-3 arguments")

    def _builtin_type_of(self, args: List[SynValue]) -> SynValue:
        return syn_text(args[0].type.name)

    def _builtin_slice(self, args: List[SynValue]) -> SynValue:
        collection = args[0]
        start = int(args[1].raw) if len(args) > 1 else 0
        end = int(args[2].raw) if len(args) > 2 else None
        if isinstance(collection.type, SynList):
            return syn_list(collection.raw[start:end])
        if isinstance(collection.type, SynText):
            return syn_text(collection.raw[start:end])
        raise RuntimeError(f"Cannot slice {collection.type.name}")

    def _builtin_fmt(self, args: List[SynValue]) -> SynValue:
        """fmt("Hello {name}, you have {count} items") — interpolate variables from caller's env."""
        template = str(args[0].raw)
        # Replace {varname} with variable values
        import re
        def replace_var(match):
            var_name = match.group(1)
            # Try to find the variable in the current environment
            # We'll use a simple approach: check if extra args were passed
            return str(var_name)  # fallback
        # For fmt, we use a map as second arg: fmt("Hi {name}", {"name": "Alice"})
        if len(args) > 1 and isinstance(args[1].type, SynMap):
            for key, val in args[1].raw.items():
                template = template.replace("{" + str(key) + "}", str(val))
        return syn_text(template)

    def _builtin_upper(self, args: List[SynValue]) -> SynValue:
        return syn_text(str(args[0].raw).upper())

    def _builtin_lower(self, args: List[SynValue]) -> SynValue:
        return syn_text(str(args[0].raw).lower())

    def _builtin_trim(self, args: List[SynValue]) -> SynValue:
        return syn_text(str(args[0].raw).strip())

    def _builtin_starts_with(self, args: List[SynValue]) -> SynValue:
        return syn_bool(str(args[0].raw).startswith(str(args[1].raw)))

    def _builtin_ends_with(self, args: List[SynValue]) -> SynValue:
        return syn_bool(str(args[0].raw).endswith(str(args[1].raw)))

    def _builtin_replace_text(self, args: List[SynValue]) -> SynValue:
        return syn_text(str(args[0].raw).replace(str(args[1].raw), str(args[2].raw)))

    # -- Regex (re) — pure, no capability. Patterns are caller-supplied; a
    #    pathological pattern can be slow (ReDoS), so never feed untrusted input
    #    as a pattern without care (see builtins.md / pitfalls.md).

    @staticmethod
    def _compile_re(pattern: str):
        import re
        try:
            return re.compile(pattern)
        except re.error as e:
            raise RuntimeError(f"invalid regex pattern {pattern!r}: {e}")

    def _builtin_matches(self, args: List[SynValue]) -> SynValue:
        """
        matches(text, pattern) → bool — true only if the WHOLE text matches the
        pattern. Built for input validation, so an unanchored pattern is already
        safe (no need to remember ^...$). For "does the pattern appear somewhere",
        use find_all / capture.
        """
        rx = self._compile_re(str(args[1].raw))
        return syn_bool(rx.fullmatch(str(args[0].raw)) is not None)

    def _builtin_find_all(self, args: List[SynValue]) -> SynValue:
        """find_all(text, pattern) → list of every (whole) match, in order."""
        rx = self._compile_re(str(args[1].raw))
        return syn_list([syn_text(m.group(0)) for m in rx.finditer(str(args[0].raw))])

    def _builtin_capture(self, args: List[SynValue]) -> SynValue:
        """
        capture(text, pattern) → first match, or nothing.

        With capture groups, returns the groups as a list (an unmatched optional
        group is `nothing`); without groups, returns the whole match as text.
        """
        rx = self._compile_re(str(args[1].raw))
        m = rx.search(str(args[0].raw))
        if m is None:
            return syn_nothing()
        if m.groups():
            return syn_list([
                syn_text(g) if g is not None else syn_nothing() for g in m.groups()
            ])
        return syn_text(m.group(0))

    def _builtin_replace_re(self, args: List[SynValue]) -> SynValue:
        """replace_re(text, pattern, replacement) → text (\\1 backrefs supported)."""
        rx = self._compile_re(str(args[1].raw))
        return syn_text(rx.sub(str(args[2].raw), str(args[0].raw)))

    def _builtin_render(self, args: List[SynValue]) -> SynValue:
        """
        render("page.html", data?) → an HTML response from a template.

        The template's { ... } holes are Synsema expressions; values are
        auto-escaped (raw(...) opts out). Reuses each/when for flow control.
        """
        # Lazy imports: server/templates import the interpreter, so importing
        # them at module load would be circular.
        from ..stdlib.templates import render_template
        from ..stdlib.server import _make_raw
        path = str(args[0].raw) if args else ""
        data = args[1] if len(args) > 1 else None
        html_str = render_template(self, path, data)
        return _make_raw(html_str, "text/html; charset=utf-8", 200)

    # =========================================================
    # Main evaluation
    # =========================================================

    def execute(self, program: ast.Program) -> SynValue:
        """Execute a full program."""
        return self._exec_block(program.statements, self.global_env)

    def _exec_block(self, statements: List[ast.Node], env: Environment) -> SynValue:
        """Execute a block of statements, return last value."""
        result = syn_nothing()
        for stmt in statements:
            result = self._exec(stmt, env)
        return result

    def _exec(self, node: ast.Node, env: Environment) -> SynValue:
        """Execute a single AST node."""
        method_name = f"_exec_{type(node).__name__}"
        method = getattr(self, method_name, None)
        if method is None:
            raise RuntimeError(
                f"No executor for node type: {type(node).__name__}",
                node.location,
            )
        return method(node, env)

    # -- Literals --

    def _exec_NumberLiteral(self, node: ast.NumberLiteral, env: Environment) -> SynValue:
        return syn_number(node.value, node.location)

    def _exec_TextLiteral(self, node: ast.TextLiteral, env: Environment) -> SynValue:
        return syn_text(node.value, node.location)

    def _exec_BoolLiteral(self, node: ast.BoolLiteral, env: Environment) -> SynValue:
        return syn_bool(node.value, node.location)

    def _exec_NothingLiteral(self, node: ast.NothingLiteral, env: Environment) -> SynValue:
        return syn_nothing(node.location)

    def _exec_ListLiteral(self, node: ast.ListLiteral, env: Environment) -> SynValue:
        elements = [self._exec(e, env) for e in node.elements]
        return syn_list(elements, node.location)

    def _exec_MapLiteral(self, node: ast.MapLiteral, env: Environment) -> SynValue:
        pairs = {}
        for key_node, val_node in node.pairs:
            key = self._exec(key_node, env)
            val = self._exec(val_node, env)
            pairs[str(key)] = val
        return syn_map(pairs, node.location)

    # -- Identifiers & Access --

    def _exec_Identifier(self, node: ast.Identifier, env: Environment) -> SynValue:
        try:
            return env.get(node.name)
        except RuntimeError:
            raise RuntimeError(f"Undefined variable: '{node.name}'", node.location)

    def _exec_PropertyAccess(self, node: ast.PropertyAccess, env: Environment) -> SynValue:
        obj = self._exec(node.object, env)
        if isinstance(obj.type, SynMap):
            if node.property_name in obj.raw:
                return obj.raw[node.property_name]
            raise RuntimeError(
                f"Map has no key '{node.property_name}'",
                node.location,
            )
        raise RuntimeError(
            f"Cannot access property '{node.property_name}' of {obj.type.name}",
            node.location,
        )

    def _exec_IndexAccess(self, node: ast.IndexAccess, env: Environment) -> SynValue:
        obj = self._exec(node.object, env)
        index = self._exec(node.index, env)
        if isinstance(obj.type, SynList):
            idx = int(index.raw)
            if idx < 0 or idx >= len(obj.raw):
                raise RuntimeError(f"Index {idx} out of bounds (list length {len(obj.raw)})", node.location)
            return obj.raw[idx]
        if isinstance(obj.type, SynMap):
            key = str(index)
            if key in obj.raw:
                return obj.raw[key]
            raise RuntimeError(f"Map has no key '{key}'", node.location)
        raise RuntimeError(f"Cannot index into {obj.type.name}", node.location)

    # -- Operators --

    def _exec_BinaryOp(self, node: ast.BinaryOp, env: Environment) -> SynValue:
        left = self._exec(node.left, env)
        right = self._exec(node.right, env)
        op = node.operator

        # Logical
        if op == "and":
            return syn_bool(left.is_truthy() and right.is_truthy(), node.location)
        if op == "or":
            return syn_bool(left.is_truthy() or right.is_truthy(), node.location)

        # String concatenation
        if op == "+" and isinstance(left.type, SynText):
            return syn_text(left.raw + str(right), node.location)
        if op == "+" and isinstance(right.type, SynText):
            return syn_text(str(left) + right.raw, node.location)

        # List concatenation
        if op == "+" and isinstance(left.type, SynList) and isinstance(right.type, SynList):
            return syn_list(left.raw + right.raw, node.location)

        # Arithmetic
        if isinstance(left.type, SynNumber) and isinstance(right.type, SynNumber):
            if op == "+":
                return syn_number(left.raw + right.raw, node.location)
            if op == "-":
                return syn_number(left.raw - right.raw, node.location)
            if op == "*":
                return syn_number(left.raw * right.raw, node.location)
            if op == "/":
                if right.raw == 0:
                    raise RuntimeError("Division by zero", node.location)
                return syn_number(left.raw / right.raw, node.location)
            if op == "%":
                return syn_number(left.raw % right.raw, node.location)
            if op == "**":
                return syn_number(left.raw ** right.raw, node.location)

        # Comparison
        if op == "==":
            return syn_bool(left.raw == right.raw, node.location)
        if op == "!=":
            return syn_bool(left.raw != right.raw, node.location)
        if op in ("<", ">", "<=", ">="):
            if isinstance(left.type, SynNumber) and isinstance(right.type, SynNumber):
                if op == "<": return syn_bool(left.raw < right.raw, node.location)
                if op == ">": return syn_bool(left.raw > right.raw, node.location)
                if op == "<=": return syn_bool(left.raw <= right.raw, node.location)
                if op == ">=": return syn_bool(left.raw >= right.raw, node.location)
            # String comparison
            if isinstance(left.type, SynText) and isinstance(right.type, SynText):
                if op == "<": return syn_bool(left.raw < right.raw, node.location)
                if op == ">": return syn_bool(left.raw > right.raw, node.location)
                if op == "<=": return syn_bool(left.raw <= right.raw, node.location)
                if op == ">=": return syn_bool(left.raw >= right.raw, node.location)

        raise RuntimeError(
            f"Unsupported operation: {left.type.name} {op} {right.type.name}",
            node.location,
        )

    def _exec_UnaryOp(self, node: ast.UnaryOp, env: Environment) -> SynValue:
        operand = self._exec(node.operand, env)
        if node.operator == "-":
            if isinstance(operand.type, SynNumber):
                return syn_number(-operand.raw, node.location)
            raise RuntimeError(f"Cannot negate {operand.type.name}", node.location)
        if node.operator == "not":
            return syn_bool(not operand.is_truthy(), node.location)
        raise RuntimeError(f"Unknown unary operator: {node.operator}", node.location)

    def _exec_PipeExpression(self, node: ast.PipeExpression, env: Environment) -> SynValue:
        """x |> f |> g  →  g(f(x))"""
        value = self._exec(node.value, env)
        for transform in node.transforms:
            # Each transform should be a callable; pass value as first arg
            func = self._exec(transform, env)
            value = self._call_value(func, [value], node.location)
        return value

    # -- Bindings --

    def _exec_LetBinding(self, node: ast.LetBinding, env: Environment) -> SynValue:
        value = self._exec(node.value, env)
        env.set(node.name, value)
        return value

    def _exec_SetMutation(self, node: ast.SetMutation, env: Environment) -> SynValue:
        value = self._exec(node.value, env)
        if isinstance(node.target, ast.Identifier):
            env.update(node.target.name, value)
        elif isinstance(node.target, ast.PropertyAccess):
            obj = self._exec(node.target.object, env)
            if isinstance(obj.type, SynMap):
                obj.raw[node.target.property_name] = value
            else:
                raise RuntimeError(f"Cannot set property on {obj.type.name}", node.location)
        elif isinstance(node.target, ast.IndexAccess):
            obj = self._exec(node.target.object, env)
            index = self._exec(node.target.index, env)
            if isinstance(obj.type, SynList):
                obj.raw[int(index.raw)] = value
            elif isinstance(obj.type, SynMap):
                obj.raw[str(index)] = value
            else:
                raise RuntimeError(f"Cannot set index on {obj.type.name}", node.location)
        else:
            raise RuntimeError("Invalid set target", node.location)
        return value

    # -- Flow control --

    def _exec_WhenStatement(self, node: ast.WhenStatement, env: Environment) -> SynValue:
        condition = self._exec(node.condition, env)
        if condition.is_truthy():
            return self._exec_block(node.body, env)
        elif node.otherwise_when:
            return self._exec(node.otherwise_when, env)
        elif node.otherwise:
            return self._exec_block(node.otherwise, env)
        return syn_nothing()

    def _exec_EachStatement(self, node: ast.EachStatement, env: Environment) -> SynValue:
        collection = self._exec(node.collection, env)
        if not isinstance(collection.type, SynList):
            raise RuntimeError(f"Cannot iterate over {collection.type.name}", node.location)
        result = syn_nothing()
        for item in collection.raw:
            loop_env = Environment(parent=env, name=f"each:{node.variable}")
            loop_env.set(node.variable, item)
            try:
                result = self._exec_block(node.body, loop_env)
            except StopSignal:
                break
        return result

    def _exec_WhileStatement(self, node: ast.WhileStatement, env: Environment) -> SynValue:
        result = syn_nothing()
        max_iterations = 1_000_000  # safety limit
        i = 0
        while i < max_iterations:
            condition = self._exec(node.condition, env)
            if not condition.is_truthy():
                break
            try:
                result = self._exec_block(node.body, env)
            except StopSignal:
                break
            i += 1
        if i >= max_iterations:
            raise RuntimeError("Loop exceeded maximum iterations (1,000,000)", node.location)
        return result

    def _exec_MatchStatement(self, node: ast.MatchStatement, env: Environment) -> SynValue:
        value = self._exec(node.value, env)
        for arm in node.arms:
            pattern = self._exec(arm.pattern, env)
            if value.raw == pattern.raw:
                return self._exec_block(arm.body, env)
        return syn_nothing()

    def _exec_StopStatement(self, node: ast.StopStatement, env: Environment) -> SynValue:
        value = syn_nothing()
        if node.value:
            value = self._exec(node.value, env)
        raise StopSignal(value)

    # -- Tasks (functions) --

    def _exec_TaskDefinition(self, node: ast.TaskDefinition, env: Environment) -> SynValue:
        # Separate require statements from the body
        required_caps = []
        body = []
        for stmt in node.body:
            if isinstance(stmt, ast.RequireStatement):
                scope_val = None
                if stmt.scope:
                    # Evaluate scope in definition context
                    scope_val = str(self._exec(stmt.scope, env))
                required_caps.append((stmt.capability, scope_val))
            else:
                body.append(stmt)

        task_val = SynTaskValue(
            name=node.name,
            parameters=node.parameters,
            body=body,
            closure_env=env,
            origin=node.location,
            required_capabilities=required_caps,
        )
        value = syn_task(task_val, node.location)
        env.set(node.name, value)
        return value

    def _exec_LambdaExpression(self, node: ast.LambdaExpression, env: Environment) -> SynValue:
        # A lambda is an anonymous task whose body is one implicit `give <expr>`,
        # closing over the current environment. The existing call path
        # (child env → bind params → exec body → catch GiveSignal) is reused as-is.
        task_val = SynTaskValue(
            name="<lambda>",
            parameters=node.parameters,
            body=[ast.GiveStatement(location=node.location, value=node.body)],
            closure_env=env,
            origin=node.location,
            required_capabilities=[],
        )
        return syn_task(task_val, node.location)

    def _exec_TaskCall(self, node: ast.TaskCall, env: Environment) -> SynValue:
        func = self._exec(node.name, env)
        args = [self._exec(a, env) for a in node.arguments]
        return self._call_value(func, args, node.location)

    def _call_value(self, func: SynValue, args: List[SynValue], location: SourceLocation) -> SynValue:
        """Call a SynValue as a function."""
        raw = func.raw

        if isinstance(raw, BuiltinTask):
            return raw.func(args)

        if isinstance(raw, SynTaskValue):
            call_env = Environment(parent=raw.closure_env, name=f"call:{raw.name}")
            for i, param in enumerate(raw.parameters):
                if i < len(args):
                    call_env.set(param, args[i])
                else:
                    call_env.set(param, syn_nothing())

            # Scoped capabilities: if the task declares require statements,
            # it runs in a restricted capability scope that ONLY has those caps
            saved_caps = None
            if raw.required_capabilities and hasattr(self, '_capability_scope_callback'):
                saved_caps = self._capability_scope_callback(
                    "push", raw.name, raw.required_capabilities
                )

            try:
                result = self._exec_block(raw.body, call_env)
            except GiveSignal as g:
                result = g.value
            finally:
                if saved_caps is not None and hasattr(self, '_capability_scope_callback'):
                    self._capability_scope_callback("pop", raw.name, saved_caps)

            return result

        raise RuntimeError(f"Cannot call value of type {func.type.name}", location)

    def _exec_GiveStatement(self, node: ast.GiveStatement, env: Environment) -> SynValue:
        value = syn_nothing()
        if node.value:
            value = self._exec(node.value, env)
        raise GiveSignal(value)

    # -- Type definition (stores as a constructor in env) --

    def _exec_TypeDefinition(self, node: ast.TypeDefinition, env: Environment) -> SynValue:
        field_names = [f[0] for f in node.fields]

        def constructor(args: List[SynValue]) -> SynValue:
            if len(args) != len(field_names):
                raise RuntimeError(
                    f"Type {node.name} expects {len(field_names)} fields, got {len(args)}",
                    node.location,
                )
            pairs = {}
            for name, val in zip(field_names, args):
                pairs[name] = val
            return syn_map(pairs, node.location)

        builtin = BuiltinTask(node.name, lambda args: constructor(args), len(field_names))
        env.set(node.name, SynValue(raw=builtin, type=SynTask()))
        return syn_nothing()

    # -- Agent system --
    # Connected to the real swarm (agents/swarm.py) via callbacks.
    # The engine wires these up. If no swarm is connected, falls back
    # to in-process execution.

    def _exec_AgentDefinition(self, node: ast.AgentDefinition, env: Environment) -> SynValue:
        """
        Register an agent definition. Does NOT execute the body.
        The body runs when the agent is spawned.
        """
        # Store the agent definition (name → AST body + parent env)
        if not hasattr(self, '_agent_definitions'):
            self._agent_definitions = {}
        self._agent_definitions[node.name] = {
            "body": node.body,
            "parent_env": env,
        }
        self.logs.append({"type": "agent_define", "name": node.name})
        # Set the agent name in env so it can be referenced
        agent_data = syn_map({"name": syn_text(node.name), "state": syn_text("defined")})
        env.set(node.name, agent_data)
        return agent_data

    def _exec_SpawnStatement(self, node: ast.SpawnStatement, env: Environment) -> SynValue:
        """
        Spawn an agent — runs its body in a real thread via the swarm.
        If no swarm is connected, runs in-process (blocking).
        """
        if not hasattr(self, '_agent_definitions'):
            self._agent_definitions = {}

        definition = self._agent_definitions.get(node.agent_name)
        if not definition:
            raise RuntimeError(f"No agent defined with name '{node.agent_name}'", node.location)

        body = definition["body"]
        parent_env = definition["parent_env"]

        # Evaluate spawn arguments
        spawn_args = {}
        for key, val_node in node.arguments.items():
            spawn_args[key] = self._exec(val_node, env)

        self.logs.append({"type": "spawn", "agent": node.agent_name, "args": list(spawn_args.keys())})

        # Use swarm callback if available (real threading)
        if hasattr(self, '_swarm_spawn') and self._swarm_spawn:
            instance_id = self._swarm_spawn(node.agent_name, body, parent_env, spawn_args)
            return syn_text(instance_id)

        # Fallback: run in-process (blocking, for simple cases)
        agent_env = Environment(parent=parent_env, name=f"agent:{node.agent_name}")
        for key, val in spawn_args.items():
            agent_env.set(key, val)
        self._exec_block(body, agent_env)
        return syn_text(f"agent:{node.agent_name}")

    def _exec_ShareStatement(self, node: ast.ShareStatement, env: Environment) -> SynValue:
        """Publish a value to the shared blackboard."""
        value = self._exec(node.value, env)
        key = str(self._exec(node.key, env))

        # Use swarm blackboard if available (thread-safe)
        if hasattr(self, '_swarm_share') and self._swarm_share:
            self._swarm_share(key, value)
        else:
            self.blackboard[key] = value

        self.logs.append({"type": "share", "key": key})
        return value

    def _exec_ObserveStatement(self, node: ast.ObserveStatement, env: Environment) -> SynValue:
        """Read a value from the shared blackboard."""
        key = str(self._exec(node.key, env))
        value = None

        # Use swarm blackboard if available (thread-safe)
        if hasattr(self, '_swarm_observe') and self._swarm_observe:
            value = self._swarm_observe(key)
        else:
            value = self.blackboard.get(key)

        if value is None:
            env.set(node.variable, syn_nothing())
            return syn_nothing()

        env.set(node.variable, value)
        return value

    def _exec_SignalStatement(self, node: ast.SignalStatement, env: Environment) -> SynValue:
        """Send a signal to other agents."""
        data = None
        if node.data:
            data = self._exec(node.data, env)

        # Use swarm signals if available (real threading.Event)
        if hasattr(self, '_swarm_signal') and self._swarm_signal:
            self._swarm_signal(node.name, data)
        self.logs.append({"type": "signal", "name": node.name})
        return syn_nothing()

    def _exec_WaitForStatement(self, node: ast.WaitForStatement, env: Environment) -> SynValue:
        """Block until a signal is received."""
        # Use swarm wait if available (real blocking)
        if hasattr(self, '_swarm_wait_for') and self._swarm_wait_for:
            result = self._swarm_wait_for(node.signal_name, timeout=30)
            if result and node.variable:
                env.set(node.variable, result)
                return result
            elif node.variable:
                env.set(node.variable, syn_nothing())
            return syn_nothing()

        # Fallback: no swarm, just log
        self.logs.append({"type": "wait_for", "signal": node.signal_name})
        if node.variable:
            env.set(node.variable, syn_nothing())
        return syn_nothing()

    # -- Capabilities --

    def _exec_RequireStatement(self, node: ast.RequireStatement, env: Environment) -> SynValue:
        scope_val = None
        if node.scope:
            scope_val = str(self._exec(node.scope, env))

        # Grant on the real CapabilitySet via callback (wired by engine)
        if hasattr(self, '_grant_capability') and self._grant_capability:
            self._grant_capability(node.capability, scope_val)

        self.capabilities.add(node.capability)
        self.logs.append({"type": "require", "capability": node.capability, "scope": scope_val})
        return syn_nothing()

    def _exec_SandboxBlock(self, node: ast.SandboxBlock, env: Environment) -> SynValue:
        sandbox_env = Environment(parent=env, name="sandbox")
        self.logs.append({"type": "sandbox_enter"})
        result = self._exec_block(node.body, sandbox_env)
        self.logs.append({"type": "sandbox_exit"})
        return result

    def _exec_InvariantDeclaration(self, node: ast.InvariantDeclaration, env: Environment) -> SynValue:
        result = self._exec(node.condition, env)
        if not result.is_truthy():
            raise RuntimeError(
                f"Invariant violation: {node.description or 'unnamed invariant'}",
                node.location,
            )
        return syn_bool(True)

    def _exec_IntentDeclaration(self, node: ast.IntentDeclaration, env: Environment) -> SynValue:
        self.logs.append({"type": "intent", "description": node.description})
        if self.intent_enforcer:
            if self._intent_frozen:
                raise RuntimeError(
                    "Cannot declare a new intent after execution has started. "
                    "Intent is frozen to prevent prompt injection from expanding the mandate.",
                    node.location,
                )
            self.intent_enforcer.set_intent(node.description)
            # Freeze after first real statement executes (done in engine)
        return syn_nothing()

    # -- Human interaction --

    def _exec_ApproveStatement(self, node: ast.ApproveStatement, env: Environment) -> SynValue:
        message = self._exec(node.message, env)
        if self.human_callback:
            result = self.human_callback("approve", str(message))
            return syn_bool(result)
        # Default: auto-approve in non-interactive mode
        self.logs.append({"type": "approve", "message": str(message), "auto": True})
        return syn_bool(True)

    def _exec_ShowStatement(self, node: ast.ShowStatement, env: Environment) -> SynValue:
        value = self._exec(node.value, env)
        if self.output_callback:
            label = f"[{node.label}] " if node.label else ""
            self.output_callback(f"{label}{value}")
        else:
            print(f"SHOW: {value}")
        return value

    def _exec_ConfirmStatement(self, node: ast.ConfirmStatement, env: Environment) -> SynValue:
        message = self._exec(node.message, env)
        if self.human_callback:
            result = self.human_callback("confirm", str(message))
            return syn_bool(result)
        self.logs.append({"type": "confirm", "message": str(message), "auto": True})
        return syn_bool(True)

    def _exec_AskExpression(self, node: ast.AskExpression, env: Environment) -> SynValue:
        prompt = self._exec(node.prompt, env)
        if self.human_callback:
            result = self.human_callback("ask", str(prompt))
            if result:
                return syn_text(str(result))
        # Non-interactive fallback: return first option if available
        if node.options:
            options = self._exec(node.options, env)
            if isinstance(options.type, SynList) and options.raw:
                return options.raw[0]
        return syn_text("")

    # -- LLM / Reasoning --

    def _exec_ReasonExpression(self, node: ast.ReasonExpression, env: Environment) -> SynValue:
        subject = self._exec(node.subject, env) if node.subject else syn_nothing()
        context = {k: self._exec(v, env) for k, v in node.context.items()}
        if self.llm_callback:
            result = self.llm_callback("reason", {
                "subject": str(subject),
                "context": {k: str(v) for k, v in context.items()},
            })
            return syn_text(str(result))
        self.logs.append({"type": "reason", "subject": str(subject)})
        return syn_text(f"[reasoning about: {subject}]")

    def _exec_DecideExpression(self, node: ast.DecideExpression, env: Environment) -> SynValue:
        options = self._exec(node.options, env) if node.options else syn_nothing()
        given = self._exec(node.given, env) if node.given else syn_nothing()
        if self.llm_callback:
            result = self.llm_callback("decide", {
                "options": str(options),
                "given": str(given),
            })
            return syn_text(str(result))
        self.logs.append({"type": "decide", "options": str(options)})
        return syn_text(f"[decision pending]")

    def _exec_AnalyzeExpression(self, node: ast.AnalyzeExpression, env: Environment) -> SynValue:
        data = self._exec(node.data, env)
        if self.llm_callback:
            result = self.llm_callback("analyze", {
                "data": str(data),
                "objective": node.objective,
            })
            return syn_text(str(result))
        self.logs.append({"type": "analyze", "objective": node.objective})
        return syn_text(f"[analysis of: {node.objective}]")

    def _exec_GenerateExpression(self, node: ast.GenerateExpression, env: Environment) -> SynValue:
        given = self._exec(node.given, env) if node.given else syn_nothing()
        params = {k: self._exec(v, env) for k, v in node.parameters.items()}
        if self.llm_callback:
            result = self.llm_callback("generate", {
                "target": node.target,
                "given": str(given),
                "parameters": {k: str(v) for k, v in params.items()},
            })
            return syn_text(str(result))
        self.logs.append({"type": "generate", "target": node.target})
        return syn_text(f"[generated: {node.target}]")

    # -- Observability --

    def _exec_TraceBlock(self, node: ast.TraceBlock, env: Environment) -> SynValue:
        import time
        entry = TraceEntry(name=node.name, location=node.location)
        self.trace.append(entry)
        start = time.perf_counter()
        result = self._exec_block(node.body, env)
        entry.duration_ms = (time.perf_counter() - start) * 1000
        entry.result = result
        return result

    def _exec_LogStatement(self, node: ast.LogStatement, env: Environment) -> SynValue:
        message = self._exec(node.message, env)
        log_entry = {
            "type": "log",
            "level": node.level,
            "message": str(message),
            "location": str(node.location),
        }
        self.logs.append(log_entry)
        if self.output_callback:
            self.output_callback(f"[LOG] {message}")
        return syn_nothing()

    def _exec_MeasureBlock(self, node: ast.MeasureBlock, env: Environment) -> SynValue:
        import time
        start = time.perf_counter()
        result = self._exec_block(node.body, env)
        elapsed = (time.perf_counter() - start) * 1000
        self.logs.append({"type": "measure", "name": node.name, "ms": elapsed})
        return result

    def _exec_CheckpointStatement(self, node: ast.CheckpointStatement, env: Environment) -> SynValue:
        state = env.dump()
        self.logs.append({
            "type": "checkpoint",
            "name": node.name,
            "state_keys": list(state.keys()),
        })
        return syn_nothing()

    # -- Error handling --

    def _exec_TryRecover(self, node: ast.TryRecover, env: Environment) -> SynValue:
        """
        Execute try block. If any exception occurs, execute recover block
        with the error message bound to the error variable.
        """
        try:
            return self._exec_block(node.try_body, env)
        except GiveSignal:
            raise  # give (return) propagates through try/recover
        except StopSignal:
            raise  # stop (break) propagates through try/recover
        except Exception as e:
            # Bind the error message to the variable
            error_msg = str(e)
            # Strip location prefix if present
            if ": " in error_msg and error_msg[0] != " ":
                parts = error_msg.split(": ", 1)
                if parts[0].count(":") >= 2:  # looks like file:line:col
                    error_msg = parts[1]
            recover_env = Environment(parent=env, name="recover")
            recover_env.set(node.error_variable, syn_text(error_msg))
            self.logs.append({
                "type": "recover",
                "error": error_msg,
                "variable": node.error_variable,
            })
            return self._exec_block(node.recover_body, recover_env)

    # -- HTTP server --

    def _exec_ServeBlock(self, node: ast.ServeBlock, env: Environment) -> SynValue:
        """
        Start an HTTP server. The actual server is implemented by the engine
        (it owns the capability set, blackboard and per-request interpreters),
        wired in via `self._serve_callback`. Without the full engine, serving
        is unavailable.
        """
        if not getattr(self, "_serve_callback", None):
            raise RuntimeError(
                "serve is only available through the Synsema engine runtime",
                node.location,
            )
        port = self._exec(node.port, env)
        self.logs.append({"type": "serve", "port": str(port)})
        return self._serve_callback(node, env, port)

    def _exec_RateLimitClause(self, node: ast.RateLimitClause, env: Environment) -> SynValue:
        """A rate_limit declaration is consumed by the serve runtime, not executed.

        It only reaches here if used outside a serve block / route (a no-op).
        """
        return syn_nothing()

    def _exec_StreamBlock(self, node: ast.StreamBlock, env: Environment) -> SynValue:
        """Run a stream block. Events are emitted by `send` via the sink."""
        return self._exec_block(node.body, env)

    def _exec_SendStatement(self, node: ast.SendStatement, env: Environment) -> SynValue:
        """Emit one SSE event through the streaming sink wired by the server."""
        value = self._exec(node.value, env)
        emit = getattr(self, "_stream_emit", None)
        if emit is None:
            raise RuntimeError(
                "send can only be used inside a stream route handler",
                node.location,
            )
        emit(value, node.event_name)
        return syn_nothing()

    def _exec_ExpectStatement(self, node: ast.ExpectStatement, env: Environment) -> SynValue:
        """
        Validate request.<target> (the parsed JSON body) against a declared
        shape. Raises ExpectViolation (→ 400) on the first mismatch.
        """
        type_map = {
            "text": SynText,
            "number": SynNumber,
            "bool": SynBool,
            "list": SynList,
            "map": SynMap,
        }
        try:
            request = env.get("request")
        except RuntimeError:
            raise ExpectViolation(
                "expect can only be used inside an HTTP route handler"
            )
        # The validated data is the request's parsed JSON body.
        data = None
        if isinstance(request.type, SynMap):
            data = request.raw.get("json")
        if data is None or not isinstance(data.type, SynMap):
            raise ExpectViolation(
                "request body is not a JSON object", expected="map"
            )
        for field_name, type_name in node.shape:
            expected_type = type_map.get(type_name)
            if expected_type is None:
                raise ExpectViolation(
                    f"unknown type '{type_name}' for field '{field_name}' "
                    f"(use: text, number, bool, list, map)",
                    field=field_name, expected=type_name,
                )
            if field_name not in data.raw:
                raise ExpectViolation(
                    f"missing required field '{field_name}' (expected {type_name})",
                    field=field_name, expected=type_name,
                )
            actual = data.raw[field_name]
            if not isinstance(actual.type, expected_type):
                raise ExpectViolation(
                    f"field '{field_name}' must be {type_name}, "
                    f"got {actual.type.name}",
                    field=field_name, expected=type_name,
                )
        return syn_nothing()

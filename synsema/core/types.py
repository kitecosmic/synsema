"""
Synsema Type System.

All values in Synsema are wrapped in SynValue, which carries:
- The actual value
- Type information
- Origin trace (where this value was created)
- Capability tags (what this value is allowed to do)

This enables full observability: every value knows where it came from
and what it's allowed to do.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from .tokens import SourceLocation


class SynType:
    """Base type marker."""
    pass


class SynText(SynType):
    name = "text"

class SynNumber(SynType):
    name = "number"

class SynBool(SynType):
    name = "bool"

class SynNothing(SynType):
    name = "nothing"

class SynList(SynType):
    name = "list"

class SynMap(SynType):
    name = "map"

class SynTask(SynType):
    """A callable task (function)."""
    name = "task"

class SynAgent(SynType):
    name = "agent"

class SynCapability(SynType):
    name = "capability"


@dataclass
class SynValue:
    """
    Every value in Synsema. Wraps the raw value with metadata.

    This is what makes the language observable: you can inspect
    any value and know its type, where it was created, and what
    capabilities it carries.
    """
    raw: Any
    type: SynType
    origin: Optional[SourceLocation] = None
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self):
        return f"SynValue({self.type.name}: {self.raw!r})"

    def __str__(self):
        if isinstance(self.type, SynNothing):
            return "nothing"
        if isinstance(self.type, SynBool):
            return "true" if self.raw else "false"
        if isinstance(self.type, SynList):
            items = ", ".join(str(v) for v in self.raw)
            return f"[{items}]"
        if isinstance(self.type, SynMap):
            pairs = ", ".join(f"{k}: {v}" for k, v in self.raw.items())
            return "{" + pairs + "}"
        return str(self.raw)

    def is_truthy(self) -> bool:
        if isinstance(self.type, SynNothing):
            return False
        if isinstance(self.type, SynBool):
            return self.raw
        if isinstance(self.type, SynNumber):
            return self.raw != 0
        if isinstance(self.type, SynText):
            return len(self.raw) > 0
        if isinstance(self.type, SynList):
            return len(self.raw) > 0
        if isinstance(self.type, SynMap):
            return len(self.raw) > 0
        return True


# -- Value constructors (convenience) --

def syn_number(value: int | float, origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=value, type=SynNumber(), origin=origin)

def syn_text(value: str, origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=value, type=SynText(), origin=origin)

def syn_bool(value: bool, origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=value, type=SynBool(), origin=origin)

def syn_nothing(origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=None, type=SynNothing(), origin=origin)

def syn_list(elements: list, origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=elements, type=SynList(), origin=origin)

def syn_map(pairs: dict, origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=pairs, type=SynMap(), origin=origin)


def syn_equals(a: SynValue, b: SynValue) -> bool:
    """Structural value equality — the language-level `==`/`!=`, `match`, and
    `contains` comparison.

    Mirrors the Rust reference `SynValue::syn_equals` (types.rs:149-204):
    recurses on `.raw`, ignoring `origin`/`metadata`, so two separately-built
    equal composites compare equal — unlike the dataclass `SynValue.__eq__`,
    which is origin-sensitive and is intentionally NOT used here.

    Note on parity: Python's value model has no distinct Secret/Server type
    (server values are a `SynMap` with metadata; there is no secret type in the
    oracle), so the Rust Secret/Server arms have no Python counterpart — server
    values fall through the Map path, as they always have.
    """
    ta, tb = a.type, b.type
    # Number/Number, Bool/Bool, and Number/Bool (Python's `True == 1`, bool is an
    # int subclass) — all faithfully captured by raw `==` on the scalar payloads.
    if isinstance(ta, (SynNumber, SynBool)) and isinstance(tb, (SynNumber, SynBool)):
        return a.raw == b.raw
    if isinstance(ta, SynText) and isinstance(tb, SynText):
        return a.raw == b.raw
    if isinstance(ta, SynNothing) and isinstance(tb, SynNothing):
        return True
    if isinstance(ta, SynList) and isinstance(tb, SynList):
        return len(a.raw) == len(b.raw) and all(
            syn_equals(x, y) for x, y in zip(a.raw, b.raw)
        )
    if isinstance(ta, SynMap) and isinstance(tb, SynMap):
        if len(a.raw) != len(b.raw):
            return False
        return all(k in b.raw and syn_equals(v, b.raw[k]) for k, v in a.raw.items())
    # everything else (incl. mismatched types, tasks) → false (mirrors Rust `_`)
    return False


@dataclass
class SynTaskValue:
    """A callable task stored as a value."""
    name: str
    parameters: List[str]
    body: Any  # List[ast.Node]
    closure_env: Any  # Environment reference
    origin: Optional[SourceLocation] = None
    required_capabilities: List[tuple] = field(default_factory=list)  # [(cap_name, scope)]

    def __repr__(self):
        return f"task {self.name}({', '.join(self.parameters)})"


def syn_task(task_val: SynTaskValue, origin: SourceLocation = None) -> SynValue:
    return SynValue(raw=task_val, type=SynTask(), origin=origin)


@dataclass
class BuiltinTask:
    """A built-in task implemented in Python."""
    name: str
    func: Callable
    param_count: int = -1  # -1 = variadic

    def __repr__(self):
        return f"builtin:{self.name}"

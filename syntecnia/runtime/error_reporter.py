"""
Syntecnia Error Reporter — Rich error diagnostics.

When something fails, a traditional language gives you:
    "Error: division by zero at line 12"

Syntecnia gives you:
    - What failed and where (file, line, column)
    - The full call stack in readable form
    - All variables visible at the point of failure
    - The source code around the error
    - What the program was trying to do (intent/trace context)
    - Suggested fixes based on the error type

This is designed for AGENTS to consume — structured, complete,
actionable. A human reading it gets clarity. An agent reading it
gets enough context to attempt a fix.
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from ..core.tokens import SourceLocation
from ..core.interpreter import Environment, TraceEntry
from ..core.types import SynValue


@dataclass
class CallFrame:
    """A single frame in the call stack."""
    task_name: str
    location: Optional[SourceLocation]
    arguments: Dict[str, str] = field(default_factory=dict)

    def __str__(self):
        loc = f" at {self.location}" if self.location else ""
        args = ", ".join(f"{k}={v}" for k, v in self.arguments.items())
        if args:
            return f"{self.task_name}({args}){loc}"
        return f"{self.task_name}{loc}"


@dataclass
class ErrorDiagnostic:
    """
    Complete diagnostic for a runtime error.

    This is the structured object an agent or human consumes
    to understand what went wrong and how to fix it.
    """
    # What happened
    error_type: str = ""           # "RuntimeError", "CapabilityViolation", etc.
    message: str = ""              # The error message
    location: Optional[SourceLocation] = None

    # Where it happened
    file: str = ""
    line: int = 0
    column: int = 0
    source_context: List[str] = field(default_factory=list)  # lines around error
    error_line_content: str = ""

    # Call stack
    call_stack: List[CallFrame] = field(default_factory=list)

    # State at failure
    visible_variables: Dict[str, str] = field(default_factory=dict)
    active_trace: Optional[str] = None   # trace block name if inside one
    active_intent: Optional[str] = None  # intent declaration

    # Suggestions
    suggestions: List[str] = field(default_factory=list)

    # For agent consumption
    error_category: str = ""  # "data", "io", "logic", "capability", "type"
    recoverable: bool = False
    retry_makes_sense: bool = False

    def format_human(self) -> str:
        """Format for human reading in terminal."""
        lines = []
        lines.append(f"{'=' * 60}")
        lines.append(f"ERROR: {self.message}")
        lines.append(f"{'=' * 60}")

        # Location
        if self.file and self.line:
            lines.append(f"\n  Location: {self.file}:{self.line}:{self.column}")

        # Intent context
        if self.active_intent:
            lines.append(f"  Intent: {self.active_intent}")
        if self.active_trace:
            lines.append(f"  Inside trace: {self.active_trace}")

        # Source context
        if self.source_context:
            lines.append(f"\n  Source:")
            for i, src_line in enumerate(self.source_context):
                line_num = self.line - len(self.source_context) // 2 + i
                marker = " >> " if line_num == self.line else "    "
                lines.append(f"  {marker}{line_num:4d} | {src_line}")

        # Call stack
        if self.call_stack:
            lines.append(f"\n  Call stack:")
            for i, frame in enumerate(self.call_stack):
                prefix = "  → " if i == 0 else "    "
                lines.append(f"  {prefix}{frame}")

        # Variables
        if self.visible_variables:
            lines.append(f"\n  Variables at failure:")
            for name, value in self.visible_variables.items():
                # Skip builtins
                if value.startswith("SynValue(task:") or value.startswith("builtin:"):
                    continue
                lines.append(f"    {name} = {value}")

        # Suggestions
        if self.suggestions:
            lines.append(f"\n  Suggestions:")
            for i, sug in enumerate(self.suggestions, 1):
                lines.append(f"    {i}. {sug}")

        # Agent metadata
        lines.append(f"\n  Category: {self.error_category}")
        lines.append(f"  Recoverable: {'yes' if self.recoverable else 'no'}")
        if self.retry_makes_sense:
            lines.append(f"  Retry may help: yes")

        lines.append(f"{'=' * 60}")
        return "\n".join(lines)

    def format_agent(self) -> Dict[str, Any]:
        """Format for agent consumption — structured data."""
        return {
            "error_type": self.error_type,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "error_category": self.error_category,
            "recoverable": self.recoverable,
            "retry_makes_sense": self.retry_makes_sense,
            "call_stack": [str(f) for f in self.call_stack],
            "variables": self.visible_variables,
            "suggestions": self.suggestions,
            "active_intent": self.active_intent,
            "active_trace": self.active_trace,
        }


# -- Error classification and suggestion engine --

ERROR_PATTERNS = [
    {
        "match": "Division by zero",
        "category": "data",
        "recoverable": True,
        "suggestions": [
            "Add a guard: when divisor != 0 before dividing",
            "Add invariant: divisor > 0 before the division",
            "Provide a default: when divisor == 0, give 0 otherwise give x / divisor",
        ],
    },
    {
        "match": "Undefined variable",
        "category": "logic",
        "recoverable": False,
        "suggestions": [
            "Check spelling of the variable name",
            "Ensure the variable is defined with 'let' before use",
            "If inside a task, check the variable is passed as parameter",
        ],
    },
    {
        "match": "Cannot iterate over",
        "category": "type",
        "recoverable": False,
        "suggestions": [
            "Ensure the value is a list before using 'each'",
            "Use type_of() to check the type at runtime",
            "Wrap single values in a list: [value]",
        ],
    },
    {
        "match": "Index .* out of bounds",
        "category": "data",
        "recoverable": True,
        "suggestions": [
            "Check length() before accessing by index",
            "Use find_first() instead of direct indexing",
            "Add invariant: index < length(list)",
        ],
    },
    {
        "match": "Cannot call value of type",
        "category": "type",
        "recoverable": False,
        "suggestions": [
            "Check that the name refers to a task, not a variable",
            "Ensure the task is defined before it's called",
            "Use type_of() to inspect the value",
        ],
    },
    {
        "match": "Capability not granted",
        "category": "capability",
        "recoverable": False,
        "suggestions": [
            "Add the matching 'require' at the top of the program",
            "Run with the --grant flag, e.g. --grant file:/path/*",
            "Check if this operation matches the declared intent",
        ],
    },
    {
        "match": "Intent violation",
        "category": "capability",
        "recoverable": False,
        "suggestions": [
            "The operation falls outside the declared intent",
            "Update the intent declaration to include this operation",
            "Run with --no-strict-intent to allow (not recommended)",
        ],
    },
    {
        "match": "Invariant violation",
        "category": "logic",
        "recoverable": True,
        "suggestions": [
            "The program state violates a declared guarantee",
            "Check the data that led to this state",
            "Add validation before the invariant point",
        ],
    },
    {
        "match": "HTTP",
        "category": "io",
        "recoverable": True,
        "retry_makes_sense": True,
        "suggestions": [
            "The external service may be temporarily unavailable",
            "Retry with exponential backoff",
            "Check if the URL and credentials are correct",
            "Use a fallback data source",
        ],
    },
    {
        "match": "Timed out",
        "category": "io",
        "recoverable": True,
        "retry_makes_sense": True,
        "suggestions": [
            "The operation took too long",
            "Increase the timeout parameter",
            "Retry — it may be a temporary slowdown",
            "Consider an async approach",
        ],
    },
    {
        "match": "File not found",
        "category": "io",
        "recoverable": True,
        "suggestions": [
            "Check that the file path is correct",
            "Use file_exists() before reading",
            "Provide a default value if the file is optional",
        ],
    },
    {
        "match": "Loop exceeded maximum iterations",
        "category": "logic",
        "recoverable": False,
        "suggestions": [
            "The loop condition never becomes false",
            "Add a counter limit or stop condition",
            "Check the loop variable is actually changing",
        ],
    },
    {
        "match": "Cannot set undefined variable",
        "category": "logic",
        "recoverable": False,
        "suggestions": [
            "Use 'let' to define the variable first, then 'set' to change it",
            "'set' only works on already-defined variables",
        ],
    },
    {
        "match": "Map has no key",
        "category": "data",
        "recoverable": True,
        "suggestions": [
            "Check if the key exists with contains()",
            "Use a default value pattern",
            "Verify the data structure with show or log",
        ],
    },
]

import re


def classify_error(message: str) -> Dict[str, Any]:
    """Classify an error message and return suggestions."""
    for pattern in ERROR_PATTERNS:
        if re.search(pattern["match"], message, re.IGNORECASE):
            return {
                "category": pattern["category"],
                "recoverable": pattern.get("recoverable", False),
                "retry_makes_sense": pattern.get("retry_makes_sense", False),
                "suggestions": pattern["suggestions"],
            }
    return {
        "category": "unknown",
        "recoverable": False,
        "retry_makes_sense": False,
        "suggestions": ["Check the error message for details"],
    }


class ErrorReporter:
    """
    Builds rich error diagnostics from runtime failures.

    Connected to the interpreter and engine, it captures all
    available context when an error occurs.
    """

    def __init__(self):
        self.source_lines: Dict[str, List[str]] = {}  # filename → lines
        self.call_stack: List[CallFrame] = []
        self.active_intent: Optional[str] = None
        self.active_traces: List[str] = []

    def load_source(self, filename: str, source: str):
        """Load source for context display."""
        self.source_lines[filename] = source.split("\n")

    def push_call(self, task_name: str, location: SourceLocation = None,
                  args: Dict[str, str] = None):
        """Push a call frame onto the stack."""
        self.call_stack.append(CallFrame(
            task_name=task_name,
            location=location,
            arguments=args or {},
        ))

    def pop_call(self):
        """Pop the current call frame."""
        if self.call_stack:
            self.call_stack.pop()

    def set_intent(self, intent: str):
        self.active_intent = intent

    def push_trace(self, name: str):
        self.active_traces.append(name)

    def pop_trace(self):
        if self.active_traces:
            self.active_traces.pop()

    def build_diagnostic(self, error: Exception,
                         env: Environment = None,
                         location: SourceLocation = None) -> ErrorDiagnostic:
        """
        Build a complete ErrorDiagnostic from an exception.

        This is called when a runtime error occurs. It captures
        everything available: location, call stack, variables,
        source context, and generates suggestions.
        """
        diag = ErrorDiagnostic()

        # Basic error info
        diag.error_type = type(error).__name__
        diag.message = str(error)

        # Location
        loc = location
        if hasattr(error, 'location') and error.location:
            loc = error.location
        if loc:
            diag.location = loc
            diag.file = loc.file
            diag.line = loc.line
            diag.column = loc.column

        # Source context (3 lines before and after)
        if loc and loc.file in self.source_lines:
            lines = self.source_lines[loc.file]
            start = max(0, loc.line - 4)
            end = min(len(lines), loc.line + 3)
            diag.source_context = lines[start:end]
            if 0 < loc.line <= len(lines):
                diag.error_line_content = lines[loc.line - 1]

        # Call stack
        diag.call_stack = list(self.call_stack)

        # Variables at failure point
        if env:
            for name, value in env.dump().items():
                diag.visible_variables[name] = str(value)

        # Trace/intent context
        diag.active_intent = self.active_intent
        diag.active_trace = self.active_traces[-1] if self.active_traces else None

        # Classification and suggestions
        classification = classify_error(diag.message)
        diag.error_category = classification["category"]
        diag.recoverable = classification["recoverable"]
        diag.retry_makes_sense = classification["retry_makes_sense"]
        diag.suggestions = classification["suggestions"]

        return diag

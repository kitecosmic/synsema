"""
Synsema Addressable Memory — Token-efficient code access.

Instead of loading entire files into context, an agent addresses
specific parts of the code:

    ref = address("file.syn:task:process_order")
    ref = address("file.syn:line:42-50")
    ref = address("file.syn:type:Customer")

This returns ONLY the relevant portion, saving tokens.
"""

from typing import Optional, Dict, Any, List
from . import ast_nodes as ast
from .parser import parse
from .ast_api import (
    find_task_by_name, find_tasks, find_types, find_agents,
    find_invariants, find_usages, summarize, get_task_dependencies,
)


class AddressResult:
    """Result of addressing a piece of code."""
    def __init__(self):
        self.found: bool = False
        self.node: Optional[ast.Node] = None
        self.source_lines: List[str] = []
        self.summary: str = ""
        self.location: Optional[str] = None
        self.metadata: Dict[str, Any] = {}

    def __str__(self):
        if self.summary:
            return self.summary
        if self.source_lines:
            return "\n".join(self.source_lines)
        return "<not found>"


class AddressableCode:
    """
    Provides token-efficient access to Synsema source code.

    An agent uses this instead of reading raw files.
    """

    def __init__(self):
        self.programs: Dict[str, ast.Program] = {}
        self.sources: Dict[str, str] = {}
        self.source_lines: Dict[str, List[str]] = {}

    def load(self, filename: str, source: str):
        """Parse and index a source file."""
        self.sources[filename] = source
        self.source_lines[filename] = source.split("\n")
        self.programs[filename] = parse(source, filename)

    def address(self, addr: str) -> AddressResult:
        """
        Resolve an address and return the relevant code portion.

        Format: <file>:<selector>:<identifier>
        """
        result = AddressResult()
        parts = addr.split(":", 2)

        if len(parts) < 2:
            result.summary = f"Invalid address: {addr}"
            return result

        filename = parts[0]
        selector = parts[1]
        identifier = parts[2] if len(parts) > 2 else ""

        if filename not in self.programs:
            result.summary = f"File not loaded: {filename}"
            return result

        program = self.programs[filename]
        lines = self.source_lines[filename]

        if selector == "summary":
            result.found = True
            result.summary = self._format_summary(summarize(program))
            result.metadata = summarize(program)
            return result

        if selector == "task":
            task = find_task_by_name(program, identifier)
            if task:
                result.found = True
                result.node = task
                result.location = f"{filename}:{task.location.line}"
                result.source_lines = self._extract_lines(lines, task.location.line)
                result.summary = f"task {task.name}({', '.join(task.parameters)})"
                result.metadata = {
                    "name": task.name,
                    "params": task.parameters,
                    "deps": get_task_dependencies(program, task.name),
                }
            return result

        if selector == "signature":
            task = find_task_by_name(program, identifier)
            if task:
                result.found = True
                result.summary = f"task {task.name}({', '.join(task.parameters)})"
            return result

        if selector == "deps":
            deps = get_task_dependencies(program, identifier)
            result.found = True
            result.summary = f"Dependencies of {identifier}: {', '.join(deps) or 'none'}"
            result.metadata = {"deps": deps}
            return result

        if selector == "type":
            for t in find_types(program):
                if t.name == identifier:
                    result.found = True
                    result.node = t
                    result.location = f"{filename}:{t.location.line}"
                    fields = ", ".join(f"{n}: {ty}" for n, ty in t.fields)
                    result.summary = f"type {t.name} ({fields})"
                    result.metadata = {"name": t.name, "fields": t.fields}
                    return result
            return result

        if selector == "agent":
            for a in find_agents(program):
                if a.name == identifier:
                    result.found = True
                    result.node = a
                    result.location = f"{filename}:{a.location.line}"
                    result.summary = f"agent {a.name}"
                    return result
            return result

        if selector == "variable":
            usages = find_usages(program, identifier)
            if usages:
                result.found = True
                locs = [f"line {u.location.line}" for u in usages[:10]]
                result.summary = f"Variable '{identifier}' used at: {', '.join(locs)}"
                result.metadata = {"usages": len(usages)}
            return result

        if selector == "line":
            try:
                if "-" in identifier:
                    start, end = identifier.split("-")
                    start_line = int(start) - 1
                    end_line = int(end)
                else:
                    start_line = int(identifier) - 1
                    end_line = start_line + 1
                result.found = True
                result.source_lines = lines[start_line:end_line]
                result.location = f"{filename}:{start_line + 1}-{end_line}"
            except ValueError:
                result.summary = f"Invalid line range: {identifier}"
            return result

        if selector == "invariant":
            invariants = find_invariants(program)
            try:
                idx = int(identifier)
                if 0 <= idx < len(invariants):
                    result.found = True
                    result.node = invariants[idx]
                    result.location = f"{filename}:{invariants[idx].location.line}"
            except (ValueError, IndexError):
                pass
            return result

        result.summary = f"Unknown selector: {selector}"
        return result

    def _extract_lines(self, lines: List[str], start_line: int,
                       max_lines: int = 30) -> List[str]:
        """Extract source lines for a node, following indentation."""
        if start_line <= 0 or start_line > len(lines):
            return []
        idx = start_line - 1
        extracted = [lines[idx]]
        base_indent = len(lines[idx]) - len(lines[idx].lstrip())

        for i in range(idx + 1, min(idx + max_lines, len(lines))):
            line = lines[i]
            if line.strip() == "":
                extracted.append(line)
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent and line.strip():
                break
            extracted.append(line)

        return extracted

    def _format_summary(self, summary: Dict) -> str:
        """Format a program summary for minimal token usage."""
        parts = []
        if summary["tasks"]:
            tasks_str = ", ".join(
                f"{t['name']}({len(t.get('params', []))} params)"
                for t in summary["tasks"]
            )
            parts.append(f"Tasks: {tasks_str}")
        if summary["types"]:
            types_str = ", ".join(t["name"] for t in summary["types"])
            parts.append(f"Types: {types_str}")
        if summary["agents"]:
            agents_str = ", ".join(a["name"] for a in summary["agents"])
            parts.append(f"Agents: {agents_str}")
        if summary["variables"]:
            vars_str = ", ".join(v["name"] for v in summary["variables"][:10])
            parts.append(f"Variables: {vars_str}")
        if summary["intents"]:
            parts.append(f"Intent: {summary['intents'][0]}")
        return " | ".join(parts)

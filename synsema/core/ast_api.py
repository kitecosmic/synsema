"""
Synsema AST Manipulation API.

This module provides structural operations on the AST that agents
can use to modify code programmatically. Instead of text search-and-replace,
agents perform semantic operations:

    - add_parameter(task, "timeout", "number")
    - rename_task(program, "old_name", "new_name")
    - insert_before(statement, new_statement)
    - wrap_in_trace(statement, "trace_name")
    - extract_task(statements, "new_task_name")
    - add_invariant(task, condition)
    - find_tasks(program, pattern)
    - find_usages(program, variable_name)

These operations are STRUCTURAL — they cannot produce syntactically
invalid code, unlike text editing.
"""

from typing import List, Optional, Dict, Callable, Any
from . import ast_nodes as ast
from .tokens import SourceLocation
from copy import deepcopy


# Dummy location for generated nodes
_GEN = SourceLocation(file="<generated>", line=0, column=0, offset=0)


# =========================================================
# Query operations — find things in the AST
# =========================================================

def find_tasks(program: ast.Program) -> List[ast.TaskDefinition]:
    """Find all task definitions in a program."""
    results = []
    _walk(program, lambda n: results.append(n) if isinstance(n, ast.TaskDefinition) else None)
    return results


def find_task_by_name(program: ast.Program, name: str) -> Optional[ast.TaskDefinition]:
    """Find a specific task by name."""
    for task in find_tasks(program):
        if task.name == name:
            return task
    return None


def find_types(program: ast.Program) -> List[ast.TypeDefinition]:
    """Find all type definitions."""
    results = []
    _walk(program, lambda n: results.append(n) if isinstance(n, ast.TypeDefinition) else None)
    return results


def find_usages(program: ast.Program, name: str) -> List[ast.Identifier]:
    """Find all usages of a variable/task name."""
    results = []
    def check(n):
        if isinstance(n, ast.Identifier) and n.name == name:
            results.append(n)
    _walk(program, check)
    return results


def find_by_type(program: ast.Program, node_type: type) -> List[ast.Node]:
    """Find all nodes of a specific type."""
    results = []
    _walk(program, lambda n: results.append(n) if isinstance(n, node_type) else None)
    return results


def find_invariants(program: ast.Program) -> List[ast.InvariantDeclaration]:
    """Find all invariant declarations."""
    return find_by_type(program, ast.InvariantDeclaration)


def find_agents(program: ast.Program) -> List[ast.AgentDefinition]:
    """Find all agent definitions."""
    return find_by_type(program, ast.AgentDefinition)


def get_task_dependencies(program: ast.Program, task_name: str) -> List[str]:
    """Get names of all tasks called by a given task."""
    task = find_task_by_name(program, task_name)
    if not task:
        return []
    calls = []
    def check(n):
        if isinstance(n, ast.TaskCall) and isinstance(n.name, ast.Identifier):
            calls.append(n.name.name)
    _walk_nodes(task.body, check)
    return list(set(calls))


def get_dependency_graph(program: ast.Program) -> Dict[str, List[str]]:
    """Get the full dependency graph of all tasks."""
    graph = {}
    for task in find_tasks(program):
        graph[task.name] = get_task_dependencies(program, task.name)
    return graph


# =========================================================
# Mutation operations — modify the AST structurally
# =========================================================

def add_parameter(task: ast.TaskDefinition, param_name: str) -> ast.TaskDefinition:
    """Add a parameter to a task definition."""
    if param_name not in task.parameters:
        task.parameters.append(param_name)
    return task


def remove_parameter(task: ast.TaskDefinition, param_name: str) -> ast.TaskDefinition:
    """Remove a parameter from a task definition."""
    if param_name in task.parameters:
        task.parameters.remove(param_name)
    return task


def rename_task(program: ast.Program, old_name: str, new_name: str) -> int:
    """
    Rename a task and all its usages. Returns count of changes.

    This is a STRUCTURAL rename — it updates:
    - The task definition
    - All call sites
    - Any identifier references
    """
    changes = 0

    def mutate(n):
        nonlocal changes
        if isinstance(n, ast.TaskDefinition) and n.name == old_name:
            n.name = new_name
            changes += 1
        if isinstance(n, ast.Identifier) and n.name == old_name:
            n.name = new_name
            changes += 1

    _walk(program, mutate)
    return changes


def rename_variable(program: ast.Program, old_name: str, new_name: str) -> int:
    """Rename a variable and all its usages."""
    changes = 0

    def mutate(n):
        nonlocal changes
        if isinstance(n, ast.Identifier) and n.name == old_name:
            n.name = new_name
            changes += 1
        if isinstance(n, ast.LetBinding) and n.name == old_name:
            n.name = new_name
            changes += 1
        if isinstance(n, ast.EachStatement) and n.variable == old_name:
            n.variable = new_name
            changes += 1

    _walk(program, mutate)
    return changes


def wrap_in_trace(statements: List[ast.Node], trace_name: str) -> ast.TraceBlock:
    """Wrap a list of statements in a trace block."""
    return ast.TraceBlock(
        location=_GEN,
        name=trace_name,
        body=statements,
    )


def wrap_in_sandbox(statements: List[ast.Node]) -> ast.SandboxBlock:
    """Wrap statements in a sandbox block."""
    return ast.SandboxBlock(
        location=_GEN,
        body=statements,
    )


def wrap_in_measure(statements: List[ast.Node], name: str) -> ast.MeasureBlock:
    """Wrap statements in a measure block for performance tracking."""
    return ast.MeasureBlock(
        location=_GEN,
        name=name,
        body=statements,
    )


def add_invariant(task: ast.TaskDefinition, condition: ast.Node,
                  description: str = "") -> ast.TaskDefinition:
    """Add an invariant check at the beginning of a task."""
    inv = ast.InvariantDeclaration(
        location=_GEN,
        condition=condition,
        description=description,
    )
    task.body.insert(0, inv)
    return task


def add_log(task: ast.TaskDefinition, message: str,
            position: str = "start") -> ast.TaskDefinition:
    """Add a log statement to a task."""
    log = ast.LogStatement(
        location=_GEN,
        message=ast.TextLiteral(location=_GEN, value=message),
    )
    if position == "start":
        task.body.insert(0, log)
    else:
        task.body.append(log)
    return task


def add_approval_gate(task: ast.TaskDefinition, message: str) -> ast.TaskDefinition:
    """Add a human approval gate at the start of a task."""
    approve = ast.ApproveStatement(
        location=_GEN,
        message=ast.TextLiteral(location=_GEN, value=message),
    )
    task.body.insert(0, approve)
    return task


def insert_statement(program: ast.Program, index: int,
                     statement: ast.Node) -> ast.Program:
    """Insert a statement at a specific position."""
    program.statements.insert(index, statement)
    return program


def remove_statement(program: ast.Program, index: int) -> ast.Node:
    """Remove and return a statement at a specific position."""
    return program.statements.pop(index)


def extract_task(program: ast.Program, start: int, end: int,
                 task_name: str, params: List[str] = None) -> ast.TaskDefinition:
    """
    Extract statements [start:end] into a new task.

    This is a structural refactoring operation:
    1. Pulls the statements out of the program
    2. Creates a new task with those statements
    3. Inserts the task definition
    4. Replaces the original statements with a call to the new task
    """
    extracted = program.statements[start:end]
    del program.statements[start:end]

    task = ast.TaskDefinition(
        location=_GEN,
        name=task_name,
        parameters=params or [],
        body=extracted,
    )

    # Insert task definition before the extraction point
    program.statements.insert(start, task)

    # Insert a call to the new task
    call = ast.TaskCall(
        location=_GEN,
        name=ast.Identifier(location=_GEN, name=task_name),
        arguments=[ast.Identifier(location=_GEN, name=p) for p in (params or [])],
    )
    program.statements.insert(start + 1, call)

    return task


def clone_task(task: ast.TaskDefinition, new_name: str) -> ast.TaskDefinition:
    """Deep-copy a task with a new name."""
    cloned = deepcopy(task)
    cloned.name = new_name
    return cloned


# =========================================================
# Code generation — create AST nodes from descriptions
# =========================================================

def make_let(name: str, value: ast.Node) -> ast.LetBinding:
    """Create: let name be value"""
    return ast.LetBinding(location=_GEN, name=name, value=value)


def make_text(value: str) -> ast.TextLiteral:
    return ast.TextLiteral(location=_GEN, value=value)


def make_number(value: float | int) -> ast.NumberLiteral:
    return ast.NumberLiteral(location=_GEN, value=value)


def make_bool(value: bool) -> ast.BoolLiteral:
    return ast.BoolLiteral(location=_GEN, value=value)


def make_identifier(name: str) -> ast.Identifier:
    return ast.Identifier(location=_GEN, name=name)


def make_call(task_name: str, *args: ast.Node) -> ast.TaskCall:
    return ast.TaskCall(
        location=_GEN,
        name=ast.Identifier(location=_GEN, name=task_name),
        arguments=list(args),
    )


def make_task(name: str, params: List[str], body: List[ast.Node]) -> ast.TaskDefinition:
    return ast.TaskDefinition(
        location=_GEN,
        name=name,
        parameters=params,
        body=body,
    )


def make_when(condition: ast.Node, body: List[ast.Node],
              otherwise: List[ast.Node] = None) -> ast.WhenStatement:
    return ast.WhenStatement(
        location=_GEN,
        condition=condition,
        body=body,
        otherwise=otherwise,
    )


def make_each(variable: str, collection: ast.Node,
              body: List[ast.Node]) -> ast.EachStatement:
    return ast.EachStatement(
        location=_GEN,
        variable=variable,
        collection=collection,
        body=body,
    )


def make_binary(left: ast.Node, op: str, right: ast.Node) -> ast.BinaryOp:
    return ast.BinaryOp(location=_GEN, left=left, operator=op, right=right)


# =========================================================
# AST summary — for agent context windows
# =========================================================

def summarize(program: ast.Program) -> Dict[str, Any]:
    """
    Generate a compact summary of a program's structure.

    This is what an agent loads into its context instead of the full code.
    It includes: task signatures, type definitions, invariants, intents,
    capabilities required, agent definitions — but NOT implementation bodies.
    """
    summary = {
        "tasks": [],
        "types": [],
        "agents": [],
        "invariants": [],
        "intents": [],
        "capabilities": [],
        "variables": [],
    }

    for stmt in program.statements:
        if isinstance(stmt, ast.TaskDefinition):
            summary["tasks"].append({
                "name": stmt.name,
                "params": stmt.parameters,
                "line": stmt.location.line,
            })
        elif isinstance(stmt, ast.TypeDefinition):
            summary["types"].append({
                "name": stmt.name,
                "fields": stmt.fields,
                "line": stmt.location.line,
            })
        elif isinstance(stmt, ast.AgentDefinition):
            summary["agents"].append({
                "name": stmt.name,
                "line": stmt.location.line,
            })
        elif isinstance(stmt, ast.InvariantDeclaration):
            summary["invariants"].append({
                "description": stmt.description,
                "line": stmt.location.line,
            })
        elif isinstance(stmt, ast.IntentDeclaration):
            summary["intents"].append(stmt.description)
        elif isinstance(stmt, ast.RequireStatement):
            summary["capabilities"].append({
                "capability": stmt.capability,
                "line": stmt.location.line,
            })
        elif isinstance(stmt, ast.LetBinding):
            summary["variables"].append({
                "name": stmt.name,
                "line": stmt.location.line,
            })

    return summary


# =========================================================
# Internal: AST walker
# =========================================================

def _walk(node: ast.Node, visitor: Callable):
    """Walk all nodes in an AST, calling visitor on each."""
    visitor(node)
    if hasattr(node, '__dataclass_fields__'):
        for field_name in node.__dataclass_fields__:
            val = getattr(node, field_name, None)
            if isinstance(val, ast.Node):
                _walk(val, visitor)
            elif isinstance(val, list):
                _walk_nodes(val, visitor)
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, ast.Node):
                        _walk(v, visitor)


def _walk_nodes(nodes: list, visitor: Callable):
    """Walk a list that may contain AST nodes."""
    for item in nodes:
        if isinstance(item, ast.Node):
            _walk(item, visitor)
        elif isinstance(item, tuple):
            for elem in item:
                if isinstance(elem, ast.Node):
                    _walk(elem, visitor)

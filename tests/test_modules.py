"""Tests for Synsema local modules: `use "..." as name` + `export`.

Covers Section 8.1 of specs/modules-spec.md. A module is imported as a map of
its exported names (orders.create == property-access + call); the module body
runs once in a fresh child env of the global env. No new runtime value type.

Fixtures live in `conformance/modules/` so they resolve the same way under both
pytest (here) and the conformance runner (which writes each entrypoint there and
resolves `use "./x.syn"` relative to it). The entrypoint source is passed to the
engine directly; only its *filename* needs to point into that dir.
"""

import os
import sys
sys.path.insert(0, "/root/Synsema")

from synsema.core.parser import parse
from synsema.core import ast_nodes as ast
from synsema.runtime.engine import SynsemaEngine


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(REPO, "conformance", "modules")
os.makedirs(MODULES_DIR, exist_ok=True)

# Fixture modules, written once at import time so they sit next to wherever the
# entrypoint runs (relative `use` resolves to the entrypoint's directory).
FIXTURES = {
    # exports create/total/tax_rate; _mk is module-private (closure-visible only)
    "orders.syn": (
        "task _mk(name, amount)\n"
        '    give {"name": name, "amount": amount}\n'
        "export task create(name, amount)\n"
        "    give _mk(name, amount)\n"
        "export task total(o)\n"
        "    give amount of o\n"
        "export let tax_rate be 0.1\n"
    ),
    # a second module with disjoint export names (alias collision test)
    "mathmod.syn": (
        "export task add(a, b)\n"
        "    give a + b\n"
        "export task mul(a, b)\n"
        "    give a * b\n"
    ),
    # export type → an importable constructor
    "shape.syn": (
        "export type Point\n"
        "    x: number\n"
        "    y: number\n"
    ),
    # circular pair a <-> b
    "a.syn": (
        'use "./b.syn" as b\n'
        "export task fa()\n"
        "    give 1\n"
    ),
    "b.syn": (
        'use "./a.syn" as a\n'
        "export task fb()\n"
        "    give 2\n"
    ),
    # forbidden: a serve block in a module
    "srv.syn": (
        "export task f()\n"
        "    give 1\n"
        "serve on 8080\n"
        '    route "GET /x"\n'
        "        give 1\n"
    ),
    # forbidden: a top-level require in a module
    "req.syn": (
        'require net("api.example.com")\n'
        "export task f()\n"
        "    give 1\n"
    ),
    # allowed: a per-task require inside a module task (sandbox as usual)
    "sb.syn": (
        "export task fetch_it()\n"
        '    require net("api.example.com")\n'
        '    give "ok"\n'
    ),
    # a top-level print runs once, at import (cache check)
    "noisy.syn": (
        'print("loaded")\n'
        "export let answer be 42\n"
    ),
    # a module that exports an enum (sum type) + a task; Hidden is NOT exported
    "ordstatus.syn": (
        "export enum OrderStatus\n"
        "    pending\n"
        "    paid(method)\n"
        "    shipped(carrier, tracking)\n"
        "enum Hidden\n"
        "    secret\n"
        "export task new_order(x)\n"
        "    give x\n"
    ),
}

for _name, _content in FIXTURES.items():
    _p = os.path.join(MODULES_DIR, _name)
    with open(_p, "w", encoding="utf-8", newline="\n") as _f:
        _f.write(_content)


def run(source: str) -> tuple:
    """Run an entrypoint whose `use "./x.syn"` resolves inside MODULES_DIR."""
    engine = SynsemaEngine()
    # The filename's directory is what relative imports resolve against; the
    # file itself need not exist on disk (the engine parses `source` directly).
    entry = os.path.join(MODULES_DIR, "__entry__.syn")
    result = engine.run_source(source, filename=entry)
    return result, result.output


def assert_output(source: str, expected: list):
    result, output = run(source)
    assert result.success, f"Program failed: {result.errors}"
    assert output == expected, f"Expected {expected}, got {output}"


def assert_fails(source: str):
    result, _ = run(source)
    assert not result.success, "Expected failure but program succeeded"


# =========================================================
# Parsing (AST shape)
# =========================================================

def test_use_parses():
    program = parse('use "./orders.syn" as orders')
    stmt = program.statements[0]
    assert isinstance(stmt, ast.UseImport)
    assert stmt.path == "./orders.syn"
    assert stmt.alias == "orders"


def test_export_task_parses():
    program = parse("export task f()\n    give 1")
    stmt = program.statements[0]
    assert isinstance(stmt, ast.ExportDeclaration)
    assert isinstance(stmt.declaration, ast.TaskDefinition)
    assert stmt.declaration.name == "f"


def test_export_let_and_type_parse():
    p1 = parse("export let x be 5")
    assert isinstance(p1.statements[0], ast.ExportDeclaration)
    assert isinstance(p1.statements[0].declaration, ast.LetBinding)
    p2 = parse("export type T\n    a: number")
    assert isinstance(p2.statements[0], ast.ExportDeclaration)
    assert isinstance(p2.statements[0].declaration, ast.TypeDefinition)


# =========================================================
# Basic import / export
# =========================================================

def test_basic_import_and_call():
    src = (
        'use "./orders.syn" as orders\n'
        'let o be orders.create("Ana", 500)\n'
        "print(text(orders.total(o)))\n"
    )
    assert_output(src, ["500"])


def test_exported_task_uses_private_helper():
    # orders.create calls the module-private _mk via closure over the module env
    src = (
        'use "./orders.syn" as orders\n'
        'let o be orders.create("Bob", 42)\n'
        "print(text(name of o))\n"
    )
    assert_output(src, ["Bob"])


def test_export_let_value():
    assert_output(
        'use "./orders.syn" as orders\nprint(text(orders.tax_rate))',
        ["0.1"],
    )


def test_export_type_constructor():
    src = (
        'use "./shape.syn" as g\n'
        "let p be g.Point(3, 4)\n"
        "print(text(x of p))\n"
    )
    assert_output(src, ["3"])


def test_two_modules_no_collision():
    src = (
        'use "./orders.syn" as orders\n'
        'use "./mathmod.syn" as m\n'
        'let o be orders.create("Z", 10)\n'
        "print(text(orders.total(o)))\n"
        "print(text(m.add(2, 3)))\n"
    )
    assert_output(src, ["10", "5"])


# =========================================================
# Isolation, caching
# =========================================================

def test_private_name_not_exported():
    assert_fails('use "./orders.syn" as orders\nprint(orders._mk("x", 1))')


def test_module_private_does_not_leak_to_importer():
    # _mk lives only in the module; the importer scope never sees it
    assert_fails('use "./orders.syn" as orders\nprint(_mk("x", 1))')


def test_caching_runs_module_once():
    # importing the same module twice runs its top-level print once
    src = (
        'use "./noisy.syn" as m\n'
        'use "./noisy.syn" as m2\n'
        "print(text(m.answer))\n"
        "print(text(m2.answer))\n"
    )
    assert_output(src, ["loaded", "42", "42"])


# =========================================================
# Circular import
# =========================================================

def test_circular_import_errors():
    assert_fails('use "./a.syn" as a\nprint(1)')


# =========================================================
# Forbidden in modules
# =========================================================

def test_serve_block_in_module_errors():
    assert_fails('use "./srv.syn" as s\nprint(1)')


def test_toplevel_require_in_module_errors():
    assert_fails('use "./req.syn" as r\nprint(1)')


def test_per_task_require_in_module_ok():
    # a per-task `require` inside a module task is allowed (sandboxes that task)
    assert_output('use "./sb.syn" as m\nprint(m.fetch_it())', ["ok"])


# =========================================================
# Path safety
# =========================================================

def test_traversal_path_errors():
    assert_fails('use "../secret.syn" as x\nprint(1)')


def test_non_syn_path_errors():
    assert_fails('use "./orders.txt" as x\nprint(1)')


def test_absolute_path_errors():
    assert_fails('use "/etc/passwd.syn" as x\nprint(1)')


def test_module_not_found_errors():
    assert_fails('use "./does_not_exist.syn" as x\nprint(1)')


# =========================================================
# export enum — modules can expose a sum type
# =========================================================

def test_export_enum_construct_and_payload():
    src = (
        'use "./ordstatus.syn" as orders\n'
        'let s be orders.OrderStatus.shipped("DHL", "ABC123")\n'
        "print(carrier of s)\n"
        "print(tracking of s)\n"
    )
    assert_output(src, ["DHL", "ABC123"])


def test_export_enum_nullary_value():
    src = 'use "./ordstatus.syn" as orders\nprint(type_of(orders.OrderStatus.pending))'
    assert_output(src, ["map"])


def test_export_enum_cross_module_match():
    src = (
        'use "./ordstatus.syn" as orders\n'
        'let s be orders.OrderStatus.shipped("DHL", "ABC123")\n'
        "match s\n"
        "    is orders.OrderStatus.pending\n"
        '        print("pendiente")\n'
        "    is orders.OrderStatus.shipped\n"
        '        print("enviado por " + carrier of s)\n'
        "    otherwise\n"
        '        print("otro")\n'
    )
    assert_output(src, ["enviado por DHL"])


def test_export_enum_otherwise_for_unhandled_variant():
    src = (
        'use "./ordstatus.syn" as orders\n'
        'let s be orders.OrderStatus.paid("card")\n'
        "match s\n"
        "    is orders.OrderStatus.shipped\n"
        '        print("enviado")\n'
        "    otherwise\n"
        '        print("otro")\n'
    )
    assert_output(src, ["otro"])


def test_export_enum_equality_cross_module():
    src = (
        'use "./ordstatus.syn" as orders\n'
        'print(text(orders.OrderStatus.shipped("DHL", "X") == orders.OrderStatus.shipped("DHL", "X")))\n'
    )
    assert_output(src, ["true"])


def test_non_exported_enum_not_visible():
    assert_fails('use "./ordstatus.syn" as orders\nprint(orders.Hidden)')


def test_export_task_alongside_enum_still_works():
    assert_output('use "./ordstatus.syn" as orders\nprint(text(orders.new_order(42)))', ["42"])


# =========================================================
# Soft-keyword regression
# =========================================================

def test_use_and_export_still_identifiers():
    assert_output("let use be 1\nlet export be 2\nprint(text(use + export))", ["3"])


def test_enum_still_identifier():
    assert_output("let enum be 1\nprint(text(enum))", ["1"])

"""Tests for Synsema enums / sum types.

Covers Section 7.1 of specs/enums-spec.md. An enum value is a tagged map
({"__variant": "Enum.variant", <fields>}); an enum type is a namespace map
({"__enum": "Enum", <variant>: value|ctor}). Construction reuses property-access
+ call; equality reuses map-equality; match gains a variant-pattern detection
(payload ignored). No new runtime value type.
"""

import sys
sys.path.insert(0, "/root/Synsema")

from synsema.core.parser import parse
from synsema.core import ast_nodes as ast
from synsema.runtime.engine import SynsemaEngine


# A reusable enum declaration prepended to most program sources.
ENUM = (
    "enum Order\n"
    "    pending\n"
    "    paid(amount)\n"
    "    shipped(date, carrier)\n"
)


def run(source: str) -> tuple:
    engine = SynsemaEngine()
    result = engine.run_source(source)
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

def test_enum_parses():
    program = parse(ENUM)
    node = program.statements[0]
    assert isinstance(node, ast.EnumDefinition)
    assert node.name == "Order"
    assert node.variants == [
        ("pending", []),
        ("paid", ["amount"]),
        ("shipped", ["date", "carrier"]),
    ]


def test_enum_soft_keyword_still_identifier():
    program = parse("let enum be 1")
    assert isinstance(program.statements[0], ast.LetBinding)


# =========================================================
# Construction + payload access
# =========================================================

def test_construct_payloaded_and_access():
    src = ENUM + 'let o be Order.shipped("2026-06-23", "DHL")\nprint(carrier of o)\nprint(date of o)'
    assert_output(src, ["DHL", "2026-06-23"])


def test_construct_nullary_and_type_of():
    assert_output(ENUM + "let s be Order.pending\nprint(type_of(s))", ["map"])


def test_construct_single_payload():
    assert_output(ENUM + "let o be Order.paid(50)\nprint(text(amount of o))", ["50"])


# =========================================================
# Match by variant
# =========================================================

def test_match_payloaded_variant():
    src = (
        ENUM
        + 'let o be Order.shipped("d", "DHL")\n'
        + "match o\n"
        + "    is Order.pending\n"
        + '        print("pendiente")\n'
        + "    is Order.shipped\n"
        + '        print("enviado por " + carrier of o)\n'
    )
    assert_output(src, ["enviado por DHL"])


def test_match_nullary_variant():
    src = (
        ENUM
        + "let o be Order.pending\n"
        + "match o\n"
        + "    is Order.paid\n"
        + '        print("paid")\n'
        + "    is Order.pending\n"
        + '        print("pendiente")\n'
    )
    assert_output(src, ["pendiente"])


def test_match_picks_right_arm_among_many():
    src = (
        ENUM
        + "let o be Order.paid(99)\n"
        + "match o\n"
        + "    is Order.pending\n"
        + '        print("p")\n'
        + "    is Order.paid\n"
        + '        print("pagado " + text(amount of o))\n'
        + "    is Order.shipped\n"
        + '        print("s")\n'
    )
    assert_output(src, ["pagado 99"])


def test_match_no_arm_matches_returns_nothing():
    # no matching arm and no `otherwise` → match yields nothing → no output
    src = (
        ENUM
        + "let o be Order.paid(50)\n"
        + "match o\n"
        + "    is Order.pending\n"
        + '        print("p")\n'
        + "    is Order.shipped\n"
        + '        print("s")\n'
    )
    assert_output(src, [])


# =========================================================
# Equality (parity-safe cases only — see report on payloaded == divergence)
# =========================================================

def test_equality_nullary_same():
    assert_output(ENUM + "print(text(Order.pending == Order.pending))", ["true"])


def test_equality_payloaded_reflexive():
    src = ENUM + 'let s be Order.shipped("a", "b")\nprint(text(s == s))'
    assert_output(src, ["true"])


def test_equality_different_variants_false():
    assert_output(ENUM + "print(text(Order.pending == Order.paid(1)))", ["false"])


# =========================================================
# Errors
# =========================================================

def test_wrong_arity_errors():
    assert_fails(ENUM + 'let o be Order.shipped("d")')


def test_too_many_args_errors():
    assert_fails(ENUM + 'let o be Order.paid(1, 2)')


def test_nullary_not_callable():
    assert_fails(ENUM + "let o be Order.pending()")


# =========================================================
# Regression — non-enum match & plain type struct unchanged
# =========================================================

def test_non_enum_match_number():
    src = (
        "let x be 9\n"
        "match x\n"
        "    is 5\n"
        '        print("five")\n'
        "    is 9\n"
        '        print("nine")\n'
    )
    assert_output(src, ["nine"])


def test_non_enum_match_text():
    src = (
        'let s be "b"\n'
        "match s\n"
        '    is "a"\n'
        '        print("A")\n'
        '    is "b"\n'
        '        print("B")\n'
    )
    assert_output(src, ["B"])


def test_plain_type_struct_still_works():
    src = (
        "type Point\n"
        "    x: number\n"
        "    y: number\n"
        "let p be Point(3, 4)\n"
        "print(text(x of p))\n"
    )
    assert_output(src, ["3"])

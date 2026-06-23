"""Tests for structural value equality — Part B of
specs/match-otherwise-and-eq-spec.md.

Python's language-level `==`/`!=`, `match` (non-enum arm), and `contains` now use
a structural `syn_equals` mirroring Rust `types.rs::syn_equals`: composites compare
by value (recursively), ignoring origin/metadata. Two separately-built equal
maps/lists are now equal — matching Rust (previously Python gave false).
"""

import sys
sys.path.insert(0, "/root/Synsema")

from synsema.runtime.engine import SynsemaEngine


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


# =========================================================
# The divergence, fixed: structural composite equality
# =========================================================

def test_equal_maps_built_separately():
    assert_output('print(text({"x": 1} == {"x": 1}))', ["true"])


def test_equal_lists_built_separately():
    assert_output("print(text([1, 2, 3] == [1, 2, 3]))", ["true"])


def test_nested_composite_equality():
    src = 'print(text({"a": [1, 2], "b": {"c": 3}} == {"a": [1, 2], "b": {"c": 3}}))'
    assert_output(src, ["true"])


def test_map_key_order_irrelevant():
    assert_output('print(text({"a": 1, "b": 2} == {"b": 2, "a": 1}))', ["true"])


def test_unequal_maps_false():
    assert_output('print(text({"x": 1} == {"x": 2}))', ["false"])
    assert_output('print(text({"x": 1} == {"x": 1, "y": 2}))', ["false"])


def test_unequal_lists_false():
    assert_output("print(text([1, 2] == [1, 2, 3]))", ["false"])
    assert_output("print(text([1, 2] == [1, 3]))", ["false"])


# =========================================================
# Payloaded-enum equality now works
# =========================================================

def test_payloaded_enum_equality():
    src = ENUM + 'print(text(Order.shipped("a", "b") == Order.shipped("a", "b")))'
    assert_output(src, ["true"])


def test_payloaded_enum_inequality():
    src = ENUM + 'print(text(Order.shipped("a", "b") == Order.shipped("a", "c")))'
    assert_output(src, ["false"])


def test_different_variants_not_equal():
    assert_output(ENUM + "print(text(Order.pending == Order.paid(1)))", ["false"])


# =========================================================
# Scalar regressions — must stay unchanged
# =========================================================

def test_scalar_equality_unchanged():
    assert_output("print(text(5 == 5))", ["true"])
    assert_output("print(text(5 == 6))", ["false"])
    assert_output('print(text("a" == "a"))', ["true"])
    assert_output('print(text("a" == "b"))', ["false"])
    assert_output("print(text(true == 1))", ["true"])  # bool-as-int
    assert_output("print(text(false == 0))", ["true"])
    assert_output("print(text(true == 2))", ["false"])
    assert_output("print(text(nothing == nothing))", ["true"])


def test_mismatched_scalar_types_false():
    assert_output('print(text("1" == 1))', ["false"])
    assert_output("print(text(nothing == 0))", ["false"])


def test_not_equal_operator():
    assert_output('print(text({"x": 1} != {"x": 1}))', ["false"])
    assert_output('print(text({"x": 1} != {"x": 2}))', ["true"])
    assert_output("print(text(5 != 6))", ["true"])


# =========================================================
# match + contains use the structural equality consistently
# =========================================================

def test_match_on_composite_uses_structural_equality():
    src = (
        'let m be {"x": 1}\n'
        "match m\n"
        '    is {"x": 1}\n'
        '        print("matched")\n'
        "    otherwise\n"
        '        print("no")\n'
    )
    assert_output(src, ["matched"])


def test_contains_uses_structural_equality():
    assert_output('print(text(contains([{"y": 2}], {"y": 2})))', ["true"])
    assert_output("print(text(contains([[1, 2], [3, 4]], [3, 4])))", ["true"])
    assert_output('print(text(contains([{"y": 2}], {"y": 3})))', ["false"])

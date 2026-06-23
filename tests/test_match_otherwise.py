"""Tests for `otherwise` (default arm) in `match` — Part A of
specs/match-otherwise-and-eq-spec.md.

`match v` runs the first `is`-arm that matches; if none match and an `otherwise`
block is present, it runs; otherwise the match yields `nothing` (unchanged).
`otherwise` is optional and must be the last arm (after all `is` arms), like in
`when`.
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
# Value-equality match + otherwise
# =========================================================

def test_otherwise_runs_when_no_arm_matches():
    src = (
        "let x be 9\n"
        "match x\n"
        "    is 5\n"
        '        print("five")\n'
        "    otherwise\n"
        '        print("other")\n'
    )
    assert_output(src, ["other"])


def test_otherwise_not_run_when_an_arm_matches():
    src = (
        "let x be 5\n"
        "match x\n"
        "    is 5\n"
        '        print("five")\n'
        "    otherwise\n"
        '        print("other")\n'
    )
    assert_output(src, ["five"])


def test_otherwise_multi_statement_block():
    src = (
        'let x be "z"\n'
        "match x\n"
        '    is "a"\n'
        '        print("A")\n'
        "    otherwise\n"
        '        print("default 1")\n'
        '        print("default 2")\n'
    )
    assert_output(src, ["default 1", "default 2"])


# =========================================================
# Enum match + otherwise (the ratified UX)
# =========================================================

def test_enum_otherwise_runs_for_unhandled_variant():
    src = (
        ENUM
        + "let o be Order.paid(50)\n"
        + "match o\n"
        + "    is Order.pending\n"
        + '        print("pendiente")\n'
        + "    is Order.shipped\n"
        + '        print("enviado")\n'
        + "    otherwise\n"
        + '        print("otro")\n'
    )
    assert_output(src, ["otro"])


def test_enum_otherwise_not_run_for_handled_variant():
    src = (
        ENUM
        + 'let o be Order.shipped("d", "DHL")\n'
        + "match o\n"
        + "    is Order.pending\n"
        + '        print("pendiente")\n'
        + "    is Order.shipped\n"
        + '        print("enviado por " + carrier of o)\n'
        + "    otherwise\n"
        + '        print("otro")\n'
    )
    assert_output(src, ["enviado por DHL"])


# =========================================================
# Regression — match without otherwise unchanged
# =========================================================

def test_no_otherwise_no_match_yields_nothing():
    src = (
        "let x be 9\n"
        "match x\n"
        "    is 5\n"
        '        print("five")\n'
    )
    assert_output(src, [])


def test_normal_is_match_still_works():
    src = (
        "let x be 9\n"
        "match x\n"
        "    is 5\n"
        '        print("five")\n'
        "    is 9\n"
        '        print("nine")\n'
    )
    assert_output(src, ["nine"])

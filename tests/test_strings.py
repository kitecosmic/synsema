"""Tests for Synsema backtick template literals: interpolation + multi-line.

Covers Section 9.1 of specs/strings-spec.md. Backtick `...{expr}...` strings
interpolate full expressions and may span real newlines; plain "..."/'...'
stay 100% unchanged (literal, single-line, no interpolation). The whole
template desugars at parse time to a `+` chain, so it always evaluates to text.
"""

import sys
sys.path.insert(0, "/root/Synsema")

from synsema.core.parser import parse
from synsema.core import ast_nodes as ast
from synsema.runtime.engine import SynsemaEngine


def run(source: str) -> tuple:
    """Helper: run source, return (result, output_lines)."""
    engine = SynsemaEngine()
    result = engine.run_source(source)
    return result, result.output


def assert_output(source: str, expected: list):
    """Assert program produces expected output lines."""
    result, output = run(source)
    assert result.success, f"Program failed: {result.errors}"
    assert output == expected, f"Expected {expected}, got {output}"


def assert_fails(source: str):
    """Assert program produces an error (lex-time or parse-time)."""
    result, _ = run(source)
    assert not result.success, "Expected failure but program succeeded"


# =========================================================
# Parsing & desugaring (AST shape)
# =========================================================

def test_pure_literal_backtick_is_text_node():
    program = parse("let s be `plain text`")
    val = program.statements[0].value
    assert isinstance(val, ast.TextLiteral)
    assert val.value == "plain text"


def test_interp_desugars_to_plus_chain():
    # `a{b}c` -> (("a" + b) + "c")
    program = parse("let s be `a{b}c`")
    val = program.statements[0].value
    assert isinstance(val, ast.BinaryOp)
    assert val.operator == "+"
    assert isinstance(val.right, ast.TextLiteral) and val.right.value == "c"
    inner = val.left
    assert isinstance(inner, ast.BinaryOp) and inner.operator == "+"
    assert isinstance(inner.left, ast.TextLiteral) and inner.left.value == "a"
    assert isinstance(inner.right, ast.Identifier) and inner.right.name == "b"


def test_leading_interp_anchors_empty_text():
    # `{x}` -> ("" + x): first operand forced to TextLiteral
    program = parse("let s be `{x}`")
    val = program.statements[0].value
    assert isinstance(val, ast.BinaryOp) and val.operator == "+"
    assert isinstance(val.left, ast.TextLiteral) and val.left.value == ""
    assert isinstance(val.right, ast.Identifier) and val.right.name == "x"


def test_plain_string_still_text_node():
    program = parse('let s be "{literal}"')
    val = program.statements[0].value
    assert isinstance(val, ast.TextLiteral)
    assert val.value == "{literal}"


# =========================================================
# Evaluation — interpolation
# =========================================================

def test_basic_interpolation():
    assert_output('let name be "Mundo"\nprint(`Hola {name}!`)', ["Hola Mundo!"])


def test_expression_interpolation():
    assert_output("print(`{1 + 2}`)", ["3"])


def test_property_expression_interpolation():
    src = 'let p be {"price": 50, "qty": 3}\nprint(`total: {price of p * qty of p}`)'
    assert_output(src, ["total: 150"])


def test_number_coercion():
    assert_output("print(`n={5}`)", ["n=5"])


def test_multiple_holes():
    src = 'let a be "x"\nlet b be "y"\nprint(`{a}-{b}-{a}`)'
    assert_output(src, ["x-y-x"])


def test_template_is_text_type():
    assert_output("print(type_of(`{5}`))", ["text"])


def test_pure_literal_runs():
    assert_output("print(`plain text`)", ["plain text"])


def test_empty_backtick():
    assert_output("print(``)", [""])


# =========================================================
# Multi-line
# =========================================================

def test_multiline_preserved():
    src = "let s be `line1\nline2`\nprint(s)"
    assert_output(src, ["line1\nline2"])


def test_multiline_with_interpolation():
    src = (
        'let base be "https://synsema.com"\n'
        'let path be "/p"\n'
        "print(`  <url>\n    <loc>{base}{path}</loc>\n  </url>`)"
    )
    assert_output(src, ["  <url>\n    <loc>https://synsema.com/p</loc>\n  </url>"])


# =========================================================
# §6 lexer subtlety — balanced braces & nested-string skipping
# =========================================================

def test_nested_braces_map_literal():
    # a map literal inside the interpolation; inner braces are balanced
    assert_output('print(`{ {"a": 1} }`)', ["{a: 1}"])


def test_nested_string_brace_does_not_close_interp():
    # the `}` inside the inner string "}" is literal, must NOT close the hole
    assert_output('print(`x{join(["}"], ",")}`)', ["x}"])


def test_nested_string_with_braces_inside():
    # braces living inside a nested string don't affect balancing
    assert_output('print(`{join(["{", "}"], "")}`)', ["{}"])


# =========================================================
# Escapes inside backticks
# =========================================================

def test_escape_literal_brace():
    assert_output(r"print(`a\{b`)", ["a{b"])


def test_escape_literal_backtick():
    assert_output(r"print(`tick:\`!`)", ["tick:`!"])


def test_escape_newline_and_tab():
    assert_output(r"print(`a\nb\tc`)", ["a\nb\tc"])


def test_escape_backslash():
    assert_output(r"print(`a\\b`)", ["a\\b"])


# =========================================================
# Regression — plain "..." / '...' are 100% unchanged
# =========================================================

def test_plain_double_quote_literal_brace():
    assert_output('print("{literal}")', ["{literal}"])


def test_plain_single_quote_literal_brace():
    assert_output("print('{literal}')", ["{literal}"])


def test_json_in_string_intact():
    assert_output(r'print("{\"id\": 1}")', ['{"id": 1}'])


def test_plain_string_no_interpolation():
    # {name} stays literal in a plain string even when name is bound
    assert_output('let name be "Mundo"\nprint("Hola {name}")', ["Hola {name}"])


def test_plain_string_newline_still_errors():
    assert_fails('print("a\nb")')


# =========================================================
# Failure cases
# =========================================================

def test_unterminated_backtick_fails():
    assert_fails("print(`unterminated")


def test_unterminated_interpolation_fails():
    assert_fails("print(`a{b`)")


def test_malformed_expression_in_hole_fails():
    assert_fails("print(`{1 +}`)")

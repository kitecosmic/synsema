"""Tests for Synsema anonymous functions (lambdas): (params) => expr.

Covers Section 9.1 of specs/lambdas-spec.md:
parsing & disambiguation, evaluation, closures, arity, and use as an
argument to every higher-order builtin — without changing those builtins.
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
    """Assert program produces an error (parse-time or run-time)."""
    result, _ = run(source)
    assert not result.success, "Expected failure but program succeeded"


# =========================================================
# Parsing & ( -disambiguation (AST shape)
# =========================================================

def test_lambda_parses_to_node():
    program = parse("let f be (x) => x + 1")
    binding = program.statements[0]
    assert isinstance(binding, ast.LetBinding)
    assert isinstance(binding.value, ast.LambdaExpression)
    assert binding.value.parameters == ["x"]
    assert isinstance(binding.value.body, ast.BinaryOp)


def test_lambda_zero_params_parses():
    program = parse("let f be () => 42")
    lam = program.statements[0].value
    assert isinstance(lam, ast.LambdaExpression)
    assert lam.parameters == []


def test_lambda_multi_params_parses():
    program = parse("let f be (a, b, c) => a")
    lam = program.statements[0].value
    assert isinstance(lam, ast.LambdaExpression)
    assert lam.parameters == ["a", "b", "c"]


def test_grouped_expression_not_lambda():
    """Regression: (1 + 2) * 3 must stay a grouped expression, not a lambda."""
    program = parse("let x be (1 + 2) * 3")
    val = program.statements[0].value
    assert isinstance(val, ast.BinaryOp)
    assert val.operator == "*"


def test_nested_parens_call_not_lambda():
    """Regression: f((x)) parses with no lambda involved."""
    program = parse("let y be identity((x))")
    call = program.statements[0].value
    assert isinstance(call, ast.TaskCall)
    # the single argument is the grouped identifier x
    assert isinstance(call.arguments[0], ast.Identifier)
    assert call.arguments[0].name == "x"


# =========================================================
# Evaluation — basics
# =========================================================

def test_apply_basic():
    assert_output("print(apply((x) => x * 2, [1, 2, 3]))", ["[2, 4, 6]"])


def test_zero_arg_lambda_called():
    assert_output("let f be () => 7\nprint(text(f()))", ["7"])


def test_lambda_is_task_type():
    assert_output("print(type_of((x) => x))", ["task"])


def test_lambda_stored_and_called():
    assert_output("let double be (x) => x * 2\nprint(text(double(21)))", ["42"])


# =========================================================
# Closures & currying
# =========================================================

def test_closure_captures_free_variable():
    src = "let y be 10\nlet f be (x) => x + y\nprint(text(f(5)))"
    assert_output(src, ["15"])


def test_curried_nested_lambda():
    src = "let curry be (m) => (n) => m * n\nlet times3 be curry(3)\nprint(text(times3(4)))"
    assert_output(src, ["12"])


# =========================================================
# Arity — fewer args bind to nothing, extra args ignored
# =========================================================

def test_missing_arg_binds_nothing():
    # b is unbound → nothing; body returns a, which is present
    assert_output("let f be (a, b) => a\nprint(text(f(5)))", ["5"])


def test_missing_arg_used_is_nothing():
    assert_output("let f be (a, b) => b\nprint(text(f(5)))", ["nothing"])


def test_extra_args_ignored():
    assert_output("let f be (x) => x\nprint(text(f(1, 2, 3)))", ["1"])


# =========================================================
# Use as an argument to the higher-order builtins
# =========================================================

def test_where_predicate():
    assert_output("print(where([1, 2, 3, 4], (x) => x > 2))", ["[3, 4]"])


def test_reduce_multi_arg():
    assert_output("print(text(reduce([1, 2, 3], (a, b) => a + b, 0)))", ["6"])


def test_find_first_predicate():
    assert_output("print(text(find_first([1, 2, 3, 4], (x) => x > 2)))", ["3"])


def test_every_predicate():
    assert_output("print(text(every([2, 4, 6], (x) => x % 2 == 0)))", ["true"])


def test_some_predicate():
    assert_output("print(text(some([1, 2, 3], (x) => x > 2)))", ["true"])


def test_count_where_predicate():
    assert_output("print(text(count_where([1, 2, 3, 4, 5], (x) => x > 2)))", ["3"])


def test_sort_by_key():
    assert_output("print(sort_by([3, 1, 2], (x) => x))", ["[1, 2, 3]"])


def test_group_by_key():
    src = "print(text(length(keys(group_by([1, 2, 3, 4], (x) => x % 2)))))"
    assert_output(src, ["2"])


def test_transform_function():
    assert_output("print(transform([1, 2, 3], (x) => x * 10))", ["[10, 20, 30]"])


def test_zip_with_combiner():
    assert_output("print(zip_with([1, 2, 3], [10, 20, 30], (a, b) => a + b))", ["[11, 22, 33]"])


def test_predicate_with_property_access():
    src = ('let products be [{"price": 100}, {"price": 30}]\n'
           "print(text(count_where(products, (p) => price of p > 50)))")
    assert_output(src, ["1"])


# =========================================================
# Regression — grouped expressions must still evaluate correctly
# =========================================================

def test_grouped_expr_arithmetic():
    assert_output("print(text((1 + 2) * 3))", ["9"])


def test_grouped_expr_both_sides():
    assert_output("print(text((2 + 3) * (4 - 1)))", ["15"])


def test_nested_parens_call_runs():
    src = "task identity(x)\n    give x\nprint(text(identity((4))))"
    assert_output(src, ["4"])


# =========================================================
# Failure cases
# =========================================================

def test_call_non_function_fails():
    assert_fails("let x be 5\nprint(x(1))")


def test_lambda_non_identifier_param_fails():
    # (1 + 2) => x : params must be identifiers
    assert_fails("let f be (1 + 2) => x")


def test_lambda_missing_body_fails():
    assert_fails("let f be () =>")

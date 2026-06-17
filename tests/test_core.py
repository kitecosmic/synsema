"""Tests for Syntecnia core: lexer, parser, interpreter."""

import sys
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.core.lexer import Lexer
from syntecnia.core.parser import Parser, parse
from syntecnia.core.interpreter import Interpreter
from syntecnia.runtime.engine import SyntecniaEngine


def run(source: str) -> tuple:
    """Helper: run source, return (result, output_lines)."""
    engine = SyntecniaEngine()
    result = engine.run_source(source)
    return result, result.output


def assert_output(source: str, expected: list):
    """Assert program produces expected output lines."""
    result, output = run(source)
    assert result.success, f"Program failed: {result.errors}"
    assert output == expected, f"Expected {expected}, got {output}"


def assert_fails(source: str):
    """Assert program produces an error."""
    result, _ = run(source)
    assert not result.success, f"Expected failure but program succeeded"


# -- Lexer tests --

def test_lexer_basic():
    lexer = Lexer('let x be 42')
    tokens = lexer.tokenize_filtered()
    types = [t.type.name for t in tokens if t.type.name not in ('NEWLINE', 'EOF')]
    assert types == ['LET', 'IDENTIFIER', 'BE', 'NUMBER'], f"Got {types}"


def test_lexer_string():
    lexer = Lexer('"hello world"')
    tokens = lexer.tokenize_filtered()
    assert tokens[0].value == "hello world"


def test_lexer_operators():
    lexer = Lexer('x + y * 2 == 10')
    tokens = lexer.tokenize_filtered()
    types = [t.type.name for t in tokens if t.type.name not in ('NEWLINE', 'EOF')]
    assert types == ['IDENTIFIER', 'PLUS', 'IDENTIFIER', 'STAR', 'NUMBER', 'EQUAL', 'NUMBER']


def test_lexer_keywords():
    lexer = Lexer('when true and not false')
    tokens = lexer.tokenize_filtered()
    types = [t.type.name for t in tokens if t.type.name not in ('NEWLINE', 'EOF')]
    assert types == ['WHEN', 'BOOL_TRUE', 'AND', 'NOT', 'BOOL_FALSE']


# -- Arithmetic and expressions --

def test_arithmetic():
    assert_output('print(text(2 + 3))', ['5'])
    assert_output('print(text(10 - 4))', ['6'])
    assert_output('print(text(3 * 7))', ['21'])
    assert_output('print(text(15 / 3))', ['5.0'])
    assert_output('print(text(2 ** 10))', ['1024'])
    assert_output('print(text(17 % 5))', ['2'])


def test_string_concatenation():
    assert_output('print("hello" + " " + "world")', ['hello world'])


def test_comparison():
    assert_output('print(text(5 > 3))', ['true'])
    assert_output('print(text(5 < 3))', ['false'])
    assert_output('print(text(5 == 5))', ['true'])
    assert_output('print(text(5 != 3))', ['true'])


# -- Variables --

def test_let_binding():
    assert_output('let x be 42\nprint(text(x))', ['42'])


def test_set_mutation():
    assert_output('let x be 1\nset x to 2\nprint(text(x))', ['2'])


# -- Flow control --

def test_when_otherwise():
    source = """
let x be 10
when x > 5
    print("big")
otherwise
    print("small")
"""
    assert_output(source, ['big'])


def test_when_otherwise_when():
    source = """
let x be 5
when x > 10
    print("big")
otherwise when x > 3
    print("medium")
otherwise
    print("small")
"""
    assert_output(source, ['medium'])


def test_each_loop():
    source = """
each i in [1, 2, 3]
    print(text(i))
"""
    assert_output(source, ['1', '2', '3'])


def test_while_loop():
    source = """
let i be 0
while i < 3
    print(text(i))
    set i to i + 1
"""
    assert_output(source, ['0', '1', '2'])


def test_match():
    source = """
let x be "b"
match x
    is "a"
        print("alpha")
    is "b"
        print("beta")
    is "c"
        print("gamma")
"""
    assert_output(source, ['beta'])


# -- Tasks (functions) --

def test_task_definition_and_call():
    source = """
task add(a, b)
    give a + b
print(text(add(3, 4)))
"""
    assert_output(source, ['7'])


def test_task_recursion():
    source = """
task factorial(n)
    when n <= 1
        give 1
    otherwise
        give n * factorial(n - 1)
print(text(factorial(5)))
"""
    assert_output(source, ['120'])


def test_task_closure():
    source = """
task make_adder(n)
    task adder(x)
        give x + n
    give adder

let add5 be make_adder(5)
print(text(add5(10)))
"""
    assert_output(source, ['15'])


# -- Data structures --

def test_list_operations():
    source = """
let lst be [1, 2, 3]
print(text(length(lst)))
let lst2 be append(lst, 4)
print(text(length(lst2)))
"""
    assert_output(source, ['3', '4'])


def test_map_operations():
    source = """
let m be {"name": "Alice", "age": 30}
print(name of m)
print(text(age of m))
"""
    assert_output(source, ['Alice', '30'])


def test_pipe_operator():
    source = """
task double(x)
    give x * 2
task inc(x)
    give x + 1
print(text(5 |> double |> inc))
"""
    assert_output(source, ['11'])


# -- Type definitions --

def test_type_definition():
    source = """
type Point
    x: number
    y: number
let p be Point(3, 4)
print(text(x of p))
print(text(y of p))
"""
    assert_output(source, ['3', '4'])


# -- Observability --

def test_trace_and_log():
    source = """
trace "test_op"
    log "inside trace"
    print("traced")
"""
    assert_output(source, ['[LOG] inside trace', 'traced'])


# -- Blackboard --

def test_share_observe():
    source = """
let data be "shared_value"
share data as "my_key"
observe "my_key" as retrieved
print(retrieved)
"""
    assert_output(source, ['shared_value'])


# -- Sandbox --

def test_sandbox():
    source = """
sandbox
    print("sandboxed")
"""
    assert_output(source, ['sandboxed'])


# -- Error handling --

def test_undefined_variable():
    assert_fails('print(undefined_var)')


def test_division_by_zero():
    assert_fails('print(text(1 / 0))')


def test_invariant_violation():
    assert_fails('let x be -1\ninvariant: x > 0')


def test_invariant_pass():
    source = 'let x be 10\ninvariant: x > 0'
    result, _ = run(source)
    assert result.success


# -- Builtins --

def test_builtin_range():
    assert_output('each i in range(3)\n    print(text(i))', ['0', '1', '2'])


def test_builtin_contains():
    assert_output('print(text(contains([1, 2, 3], 2)))', ['true'])
    assert_output('print(text(contains("hello", "ell")))', ['true'])


def test_builtin_split_join():
    assert_output('print(text(length(split("a,b,c", ","))))', ['3'])
    assert_output('print(join(["a", "b", "c"], "-"))', ['a-b-c'])


def test_builtin_type_of():
    assert_output('print(type_of(42))', ['number'])
    assert_output('print(type_of("hi"))', ['text'])
    assert_output('print(type_of([1]))', ['list'])


# -- Run all tests --

if __name__ == "__main__":
    test_functions = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test_fn in test_functions:
        try:
            test_fn()
            passed += 1
            print(f"  PASS: {test_fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL: {test_fn.__name__}: {e}")

    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests")
    sys.exit(1 if failed else 0)

"""Tests for advanced Syntecnia features: AST API, testgen, intentional ops,
speculative execution, resource locking, addressable memory, flat syntax."""

import sys
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.runtime.engine import SyntecniaEngine
from syntecnia.core.parser import parse
from syntecnia.core import ast_api
from syntecnia.core.testgen import TestGenerator
from syntecnia.core.addressable import AddressableCode
from syntecnia.core.flat_syntax import translate_flat
from syntecnia.runtime.speculative import SpeculativeEngine, EnvironmentSnapshot
from syntecnia.core.interpreter import Interpreter, Environment
from syntecnia.core.types import syn_number, syn_text
from syntecnia.agents.resource_lock import ResourceLockManager, LockMode, LockStatus


# ===== AST API =====

SAMPLE_PROGRAM = """
task add(a, b)
    give a + b

task multiply(a, b)
    give a * b

task compute(x)
    let doubled be add(x, x)
    give multiply(doubled, 3)

type Point
    x: number
    y: number

let result be compute(5)
"""

def test_ast_find_tasks():
    program = parse(SAMPLE_PROGRAM)
    tasks = ast_api.find_tasks(program)
    names = [t.name for t in tasks]
    assert "add" in names
    assert "multiply" in names
    assert "compute" in names


def test_ast_find_task_by_name():
    program = parse(SAMPLE_PROGRAM)
    task = ast_api.find_task_by_name(program, "add")
    assert task is not None
    assert task.parameters == ["a", "b"]


def test_ast_find_types():
    program = parse(SAMPLE_PROGRAM)
    types = ast_api.find_types(program)
    assert len(types) == 1
    assert types[0].name == "Point"


def test_ast_find_usages():
    program = parse(SAMPLE_PROGRAM)
    usages = ast_api.find_usages(program, "compute")
    assert len(usages) >= 1


def test_ast_dependency_graph():
    program = parse(SAMPLE_PROGRAM)
    graph = ast_api.get_dependency_graph(program)
    assert "add" in graph["compute"]
    assert "multiply" in graph["compute"]


def test_ast_rename_task():
    program = parse(SAMPLE_PROGRAM)
    changes = ast_api.rename_task(program, "add", "sum")
    assert changes >= 2  # definition + usage


def test_ast_add_parameter():
    program = parse(SAMPLE_PROGRAM)
    task = ast_api.find_task_by_name(program, "add")
    ast_api.add_parameter(task, "c")
    assert "c" in task.parameters


def test_ast_summarize():
    program = parse(SAMPLE_PROGRAM)
    summary = ast_api.summarize(program)
    assert len(summary["tasks"]) == 3
    assert len(summary["types"]) == 1


def test_ast_make_helpers():
    node = ast_api.make_call("print", ast_api.make_text("hello"))
    assert node.name.name == "print"


def test_ast_extract_task():
    program = parse("let a be 1\nlet b be 2\nlet c be a + b\nprint(text(c))")
    task = ast_api.extract_task(program, 0, 2, "setup", [])
    assert task.name == "setup"


# ===== Test Generator =====

def test_testgen_generates_cases():
    gen = TestGenerator()
    gen.load_program("""
task double(x)
    give x * 2

type Item
    name: text
    price: number
""")
    cases = gen.generate_all()
    assert len(cases) > 0
    # Should have task tests and type tests
    task_tests = [c for c in cases if c.task_name == "double"]
    type_tests = [c for c in cases if "Item" in c.task_name]
    assert len(task_tests) > 0
    assert len(type_tests) > 0


def test_testgen_runs_and_reports():
    gen = TestGenerator()
    gen.load_program("""
task add(a, b)
    give a + b
""")
    cases = gen.generate_all()
    stats = gen.run_all(cases)
    assert stats["total"] > 0
    report = gen.format_report(cases, stats)
    assert "Test Generation Report" in report


# ===== Intentional Operations =====

def test_intentional_apply():
    engine = SyntecniaEngine()
    result = engine.run_source("""
task double(x)
    give x * 2
let nums be [1, 2, 3, 4, 5]
let doubled be apply(double, nums)
each n in doubled
    print(text(n))
""")
    assert result.success
    assert result.output == ["2", "4", "6", "8", "10"]


def test_intentional_where():
    engine = SyntecniaEngine()
    result = engine.run_source("""
task is_big(x)
    give x > 3
let nums be [1, 2, 3, 4, 5]
let big be where(nums, is_big)
print(text(length(big)))
""")
    assert result.success
    assert result.output == ["2"]


def test_intentional_reduce():
    engine = SyntecniaEngine()
    result = engine.run_source("""
task add(acc, x)
    give acc + x
let total be reduce([1, 2, 3, 4, 5], add, 0)
print(text(total))
""")
    assert result.success
    assert result.output == ["15"]


def test_intentional_collect():
    engine = SyntecniaEngine()
    result = engine.run_source("""
let users be [{"name": "Alice"}, {"name": "Bob"}]
let names be collect(users, "name")
each n in names
    print(n)
""")
    assert result.success
    assert result.output == ["Alice", "Bob"]


def test_intentional_transform():
    engine = SyntecniaEngine()
    result = engine.run_source("""
task double(x)
    give x * 2
task is_even(x)
    give x % 2 == 0
let nums be [1, 2, 3, 4]
let result be transform(nums, double, is_even)
each n in result
    print(text(n))
""")
    assert result.success
    assert result.output == ["1", "4", "3", "8"]


def test_intentional_sort_by():
    engine = SyntecniaEngine()
    result = engine.run_source("""
task neg(x)
    give 0 - x
let nums be [3, 1, 4, 1, 5]
let sorted be sort_by(nums, neg)
each n in sorted
    print(text(n))
""")
    assert result.success
    assert result.output == ["5", "4", "3", "1", "1"]


def test_intentional_every_some():
    engine = SyntecniaEngine()
    result = engine.run_source("""
task positive(x)
    give x > 0
print(text(every([1, 2, 3], positive)))
print(text(every([-1, 2, 3], positive)))
print(text(some([-1, -2, 3], positive)))
print(text(some([-1, -2, -3], positive)))
""")
    assert result.success
    assert result.output == ["true", "false", "true", "false"]


def test_intentional_flatten():
    engine = SyntecniaEngine()
    result = engine.run_source("""
let nested be [[1, 2], [3, 4], [5]]
let flat be flatten(nested)
print(text(length(flat)))
""")
    assert result.success
    assert result.output == ["5"]


# ===== Speculative Execution =====

def test_speculative_rollback():
    interp = Interpreter()
    env = interp.global_env
    env.set("x", syn_number(10))

    spec = SpeculativeEngine()
    ctx = spec.begin(env, "test")

    # Modify x
    env.set("x", syn_number(999))
    assert env.get("x").raw == 999

    # Rollback
    spec.rollback(ctx)
    assert env.get("x").raw == 10


def test_speculative_commit():
    interp = Interpreter()
    env = interp.global_env
    env.set("x", syn_number(10))

    spec = SpeculativeEngine()
    ctx = spec.begin(env, "test")

    env.set("x", syn_number(42))
    spec.commit(ctx)

    assert env.get("x").raw == 42


def test_speculative_fork():
    interp = Interpreter()
    env = interp.global_env
    env.set("x", syn_number(10))

    spec = SpeculativeEngine()

    def branch_a(interp, branch_env):
        branch_env.set("x", syn_number(100))
        return syn_text("a")

    def branch_b(interp, branch_env):
        branch_env.set("x", syn_number(200))
        return syn_text("b")

    results = spec.fork(env, [branch_a, branch_b], interp)
    assert len(results) == 2
    assert str(results[0][0]) == "a"
    assert str(results[1][0]) == "b"

    # Choose branch B
    spec.choose_and_apply(env, results, 1)
    assert env.get("x").raw == 200


# ===== Resource Locking =====

def test_resource_lock_acquire_release():
    mgr = ResourceLockManager()
    status = mgr.acquire("file.txt", "agent1")
    assert status == LockStatus.ACQUIRED
    assert mgr.is_locked("file.txt")

    mgr.release("file.txt", "agent1")
    assert not mgr.is_locked("file.txt")


def test_resource_lock_exclusive_blocks():
    mgr = ResourceLockManager()
    mgr.acquire("file.txt", "agent1", LockMode.EXCLUSIVE)
    status = mgr.acquire("file.txt", "agent2", LockMode.EXCLUSIVE, timeout=0)
    assert status == LockStatus.DENIED


def test_resource_lock_shared_allows():
    mgr = ResourceLockManager()
    mgr.acquire("file.txt", "agent1", LockMode.SHARED)
    status = mgr.acquire("file.txt", "agent2", LockMode.SHARED)
    assert status == LockStatus.ACQUIRED


def test_resource_lock_shared_blocks_exclusive():
    mgr = ResourceLockManager()
    mgr.acquire("file.txt", "agent1", LockMode.SHARED)
    status = mgr.acquire("file.txt", "agent2", LockMode.EXCLUSIVE, timeout=0)
    assert status == LockStatus.DENIED


def test_resource_lock_conflict_map():
    mgr = ResourceLockManager()
    mgr.acquire("file_a", "agent1")
    mgr.acquire("file_b", "agent2")
    mgr.acquire("file_b", "agent2", LockMode.SHARED)  # re-acquire ok
    cmap = mgr.get_conflict_map()
    assert "file_a" in cmap
    assert "file_b" in cmap


def test_resource_lock_release_all():
    mgr = ResourceLockManager()
    mgr.acquire("a", "agent1")
    mgr.acquire("b", "agent1")
    mgr.acquire("c", "agent2")
    mgr.release_all("agent1")
    assert not mgr.is_locked("a")
    assert not mgr.is_locked("b")
    assert mgr.is_locked("c")


# ===== Addressable Memory =====

def test_addressable_summary():
    ac = AddressableCode()
    ac.load("test.syn", SAMPLE_PROGRAM)
    result = ac.address("test.syn:summary")
    assert result.found
    assert "add" in result.summary
    assert "Point" in result.summary


def test_addressable_task():
    ac = AddressableCode()
    ac.load("test.syn", SAMPLE_PROGRAM)
    result = ac.address("test.syn:task:add")
    assert result.found
    assert "add" in result.summary
    assert result.metadata["params"] == ["a", "b"]


def test_addressable_signature():
    ac = AddressableCode()
    ac.load("test.syn", SAMPLE_PROGRAM)
    result = ac.address("test.syn:signature:compute")
    assert result.found
    assert "compute" in result.summary
    assert result.source_lines == []  # signature only, no body


def test_addressable_deps():
    ac = AddressableCode()
    ac.load("test.syn", SAMPLE_PROGRAM)
    result = ac.address("test.syn:deps:compute")
    assert result.found
    assert "add" in result.metadata["deps"]


def test_addressable_type():
    ac = AddressableCode()
    ac.load("test.syn", SAMPLE_PROGRAM)
    result = ac.address("test.syn:type:Point")
    assert result.found
    assert "Point" in result.summary


def test_addressable_line_range():
    ac = AddressableCode()
    ac.load("test.syn", SAMPLE_PROGRAM)
    result = ac.address("test.syn:line:1-3")
    assert result.found
    assert len(result.source_lines) == 3


# ===== Flat Syntax =====

def test_flat_when_comma():
    flat = 'When x > 5, print("big").'
    std = translate_flat(flat)
    assert "when x > 5" in std
    assert 'print("big")' in std


def test_flat_otherwise():
    flat = 'Otherwise, print("small").'
    std = translate_flat(flat)
    assert "otherwise" in std
    assert 'print("small")' in std


def test_flat_task_block():
    flat = """task greet(name):
    Let msg be "Hello " + name.
    Give msg.
end"""
    std = translate_flat(flat)
    assert "task greet(name)" in std
    assert "let msg be" in std
    assert "give msg" in std


def test_flat_for_each():
    flat = 'For each item in list, print(item).'
    std = translate_flat(flat)
    assert "each item in list" in std


def test_flat_full_program():
    flat = """-- A flat syntax program
task double(x):
    Give x * 2.
end

let nums be [1, 2, 3]
For each n in nums, print(text(double(n))).
"""
    std = translate_flat(flat)
    engine = SyntecniaEngine()
    result = engine.run_source(std)
    assert result.success
    assert result.output == ["2", "4", "6"]


# ===== Run all =====

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

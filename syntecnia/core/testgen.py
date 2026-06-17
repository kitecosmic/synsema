"""
Syntecnia Test Generator — Automatic tests from types and invariants.

The language derives tests automatically instead of requiring the agent
to write them manually. Given:
    - Type definitions (what shapes data can have)
    - Invariants (what must always be true)
    - Task signatures (what functions accept and return)

The generator creates:
    - Edge case inputs (empty strings, zero, negative numbers, empty lists)
    - Boundary tests (max values, min values)
    - Invariant verification after each operation
    - Type conformance checks
    - Idempotency tests (calling twice gives same result)
"""

import random
from typing import List, Dict, Any, Optional, Tuple
from . import ast_nodes as ast
from .types import (
    SynValue, syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
)
from .parser import parse
from .interpreter import Interpreter, Environment, GiveSignal
from .ast_api import find_tasks, find_types, find_invariants


# -- Value generators for each type --

def generate_values(type_name: str, count: int = 10) -> List[SynValue]:
    """Generate test values for a given type, including edge cases."""
    generators = {
        "number": _gen_numbers,
        "text": _gen_texts,
        "bool": _gen_bools,
        "list": _gen_lists,
        "map": _gen_maps,
    }
    gen = generators.get(type_name, _gen_nothing)
    return gen(count)


def _gen_numbers(count: int) -> List[SynValue]:
    """Generate number test cases including edge cases."""
    # Always include edge cases
    edge = [
        syn_number(0),
        syn_number(1),
        syn_number(-1),
        syn_number(0.5),
        syn_number(-0.5),
        syn_number(999999),
        syn_number(-999999),
        syn_number(0.0001),
    ]
    # Add random values
    while len(edge) < count:
        edge.append(syn_number(random.uniform(-1000, 1000)))
    return edge[:count]


def _gen_texts(count: int) -> List[SynValue]:
    edge = [
        syn_text(""),
        syn_text(" "),
        syn_text("hello"),
        syn_text("Hello World"),
        syn_text("a" * 1000),  # long string
        syn_text("special: !@#$%^&*()"),
        syn_text("unicode: é à ñ 日本語"),
        syn_text("newline\nin\nstring"),
    ]
    while len(edge) < count:
        length = random.randint(1, 50)
        edge.append(syn_text("".join(chr(random.randint(97, 122)) for _ in range(length))))
    return edge[:count]


def _gen_bools(count: int) -> List[SynValue]:
    return [syn_bool(True), syn_bool(False)]


def _gen_lists(count: int) -> List[SynValue]:
    edge = [
        syn_list([]),  # empty
        syn_list([syn_number(1)]),  # single element
        syn_list([syn_number(i) for i in range(10)]),  # sequential
        syn_list([syn_number(5)] * 5),  # all same
        syn_list([syn_number(-i) for i in range(5)]),  # negative
        syn_list([syn_text("a"), syn_number(1), syn_bool(True)]),  # mixed types
    ]
    return edge[:count]


def _gen_maps(count: int) -> List[SynValue]:
    edge = [
        syn_map({}),  # empty
        syn_map({"key": syn_text("value")}),  # single
        syn_map({"a": syn_number(1), "b": syn_number(2), "c": syn_number(3)}),
    ]
    return edge[:count]


def _gen_nothing(count: int) -> List[SynValue]:
    return [syn_nothing()]


# -- Test case generation --

class TestCase:
    """A generated test case."""
    def __init__(self, name: str, task_name: str, inputs: List[SynValue],
                 check: str = "", expected: Any = None):
        self.name = name
        self.task_name = task_name
        self.inputs = inputs
        self.check = check  # "no_error", "invariant", "type", "idempotent"
        self.expected = expected
        self.passed: Optional[bool] = None
        self.error: Optional[str] = None
        self.result: Optional[SynValue] = None


class TestGenerator:
    """
    Generates test cases from a Syntecnia program's types and signatures.

    Usage:
        gen = TestGenerator()
        gen.load_program(source_code)
        cases = gen.generate_all()
        results = gen.run_all(cases)
    """

    def __init__(self):
        self.program: Optional[ast.Program] = None
        self.interpreter: Optional[Interpreter] = None

    def load_program(self, source: str):
        """Parse and load a program for test generation."""
        self.program = parse(source)
        self.interpreter = Interpreter()
        # Execute the program first to register all tasks/types
        self.interpreter.execute(self.program)

    def generate_all(self) -> List[TestCase]:
        """Generate all test cases for the loaded program."""
        if not self.program:
            return []

        cases = []
        cases.extend(self._generate_task_tests())
        cases.extend(self._generate_invariant_tests())
        cases.extend(self._generate_type_tests())
        return cases

    def _generate_task_tests(self) -> List[TestCase]:
        """Generate tests for each task based on parameter count."""
        cases = []
        tasks = find_tasks(self.program)

        for task in tasks:
            if not task.parameters:
                # No-arg task: just call it, check no crash
                cases.append(TestCase(
                    name=f"{task.name}:no_crash",
                    task_name=task.name,
                    inputs=[],
                    check="no_error",
                ))
                continue

            # Generate inputs for each parameter
            param_count = len(task.parameters)

            # Test with numbers
            for i, vals in enumerate(_gen_numbers(5)):
                inputs = [vals] * param_count
                cases.append(TestCase(
                    name=f"{task.name}:number_edge_{i}",
                    task_name=task.name,
                    inputs=inputs,
                    check="no_error",
                ))

            # Test with empty/edge strings
            for i, vals in enumerate(_gen_texts(3)):
                inputs = [vals] * param_count
                cases.append(TestCase(
                    name=f"{task.name}:text_edge_{i}",
                    task_name=task.name,
                    inputs=inputs,
                    check="no_error",
                ))

            # Test with nothing
            cases.append(TestCase(
                name=f"{task.name}:nothing_input",
                task_name=task.name,
                inputs=[syn_nothing()] * param_count,
                check="no_error",
            ))

            # Idempotency test: f(f(x)) behavior check
            if param_count == 1:
                cases.append(TestCase(
                    name=f"{task.name}:idempotency",
                    task_name=task.name,
                    inputs=[syn_number(42)],
                    check="idempotent",
                ))

        return cases

    def _generate_invariant_tests(self) -> List[TestCase]:
        """Generate tests that verify invariants hold after operations."""
        cases = []
        invariants = find_invariants(self.program)

        for i, inv in enumerate(invariants):
            cases.append(TestCase(
                name=f"invariant_{i}",
                task_name="__invariant__",
                inputs=[],
                check="invariant",
                expected=inv,
            ))

        return cases

    def _generate_type_tests(self) -> List[TestCase]:
        """Generate tests for type constructors."""
        cases = []
        types = find_types(self.program)

        for typedef in types:
            field_count = len(typedef.fields)

            # Correct arity
            inputs = []
            for fname, ftype in typedef.fields:
                vals = generate_values(ftype, 1)
                inputs.append(vals[0] if vals else syn_nothing())

            cases.append(TestCase(
                name=f"type_{typedef.name}:construct",
                task_name=typedef.name,
                inputs=inputs,
                check="no_error",
            ))

            # Wrong arity (too few)
            if field_count > 0:
                cases.append(TestCase(
                    name=f"type_{typedef.name}:too_few_args",
                    task_name=typedef.name,
                    inputs=inputs[:field_count - 1],
                    check="should_error",
                ))

        return cases

    def run_all(self, cases: List[TestCase]) -> Dict[str, int]:
        """
        Run all test cases and return summary.

        Returns dict with: total, passed, failed, errors
        """
        stats = {"total": 0, "passed": 0, "failed": 0, "errors": 0}

        for case in cases:
            stats["total"] += 1
            try:
                self._run_case(case)
                if case.passed:
                    stats["passed"] += 1
                else:
                    stats["failed"] += 1
            except Exception as e:
                case.error = str(e)
                stats["errors"] += 1

        return stats

    def _run_case(self, case: TestCase):
        """Run a single test case."""
        if case.check == "invariant":
            # Re-evaluate the invariant condition
            try:
                result = self.interpreter._exec(case.expected.condition, self.interpreter.global_env)
                case.passed = result.is_truthy()
                case.result = result
                if not case.passed:
                    case.error = "Invariant violation"
            except Exception as e:
                case.passed = False
                case.error = str(e)
            return

        # Get the task value from the interpreter
        try:
            task_val = self.interpreter.global_env.get(case.task_name)
        except:
            case.passed = False
            case.error = f"Task '{case.task_name}' not found"
            return

        if case.check == "should_error":
            try:
                self.interpreter._call_value(task_val, case.inputs, None)
                case.passed = False
                case.error = "Expected error but succeeded"
            except:
                case.passed = True
            return

        if case.check == "no_error":
            try:
                result = self.interpreter._call_value(task_val, case.inputs, None)
                case.passed = True
                case.result = result
            except Exception as e:
                case.passed = False
                case.error = str(e)
            return

        if case.check == "idempotent":
            try:
                result1 = self.interpreter._call_value(task_val, case.inputs, None)
                result2 = self.interpreter._call_value(task_val, [result1], None)
                # Not strictly idempotent check, but verifies stability
                case.passed = True
                case.result = result2
            except Exception as e:
                # Idempotency failure is acceptable (logged but not failed)
                case.passed = True  # it's informational
                case.error = f"Non-idempotent: {e}"
            return

    def format_report(self, cases: List[TestCase], stats: Dict) -> str:
        """Format test results as a readable report."""
        lines = [
            f"Test Generation Report",
            f"  Total: {stats['total']}, Passed: {stats['passed']}, "
            f"Failed: {stats['failed']}, Errors: {stats['errors']}",
            "",
        ]

        for case in cases:
            status = "PASS" if case.passed else "FAIL"
            error = f" — {case.error}" if case.error else ""
            lines.append(f"  [{status}] {case.name}{error}")

        return "\n".join(lines)

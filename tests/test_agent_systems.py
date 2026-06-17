"""Tests for agent progress, memory, and rules."""
import sys
import time
import tempfile
import os
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.agents.progress import (
    ProgressManager, TaskProgress, TaskStep, StepStatus,
)
from syntecnia.agents.memory import (
    AgentMemory, MemoryEntry, OwnerRule, RuleLevel, RuleViolation,
)
from syntecnia.runtime.engine import SyntecniaEngine


# ===== Progress Tracking =====

def test_progress_create():
    mgr = ProgressManager()
    p = mgr.create("job1", ["fetch", "process", "save"])
    assert len(p.steps) == 3
    assert p.progress_percent == 0


def test_progress_step_lifecycle():
    mgr = ProgressManager()
    mgr.create("job", ["a", "b", "c"])
    mgr.start_step("job", "a")
    assert mgr.tasks["job"].current_step().name == "a"
    mgr.complete_step("job", "a", "done!")
    assert mgr.tasks["job"].steps[0].status == StepStatus.DONE
    assert abs(mgr.tasks["job"].progress_percent - 33.33) < 1


def test_progress_resume_point():
    mgr = ProgressManager()
    mgr.create("job", ["a", "b", "c"])
    mgr.start_step("job", "a")
    mgr.complete_step("job", "a")
    # Resume should be "b" (first pending)
    assert mgr.get_resume_point("job") == "b"


def test_progress_resume_after_failure():
    mgr = ProgressManager()
    mgr.create("job", ["a", "b", "c"])
    mgr.start_step("job", "a")
    mgr.complete_step("job", "a")
    mgr.start_step("job", "b")
    mgr.fail_step("job", "b", "connection lost")
    # Resume should be "b" (retry failed step)
    assert mgr.get_resume_point("job") == "b"


def test_progress_resume_mid_step():
    mgr = ProgressManager()
    mgr.create("job", ["a", "b", "c"])
    mgr.start_step("job", "a")
    # Crash here — step a is still IN_PROGRESS
    assert mgr.get_resume_point("job") == "a"


def test_progress_complete():
    mgr = ProgressManager()
    mgr.create("job", ["a", "b"])
    mgr.start_step("job", "a")
    mgr.complete_step("job", "a")
    mgr.start_step("job", "b")
    mgr.complete_step("job", "b")
    assert mgr.tasks["job"].is_complete
    assert mgr.tasks["job"].progress_percent == 100


def test_progress_display():
    mgr = ProgressManager()
    mgr.create("sync", ["fetch", "validate", "update"])
    mgr.start_step("sync", "fetch")
    mgr.complete_step("sync", "fetch", "100 items")
    mgr.start_step("sync", "validate")
    display = mgr.tasks["sync"].format_display()
    assert "OK" in display
    assert ">>" in display
    assert "100 items" in display


def test_progress_persistence():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        mgr = ProgressManager(persist_path=path)
        mgr.create("job", ["a", "b"])
        mgr.start_step("job", "a")
        mgr.complete_step("job", "a")

        mgr2 = ProgressManager(persist_path=path)
        mgr2.load()
        assert "job" in mgr2.tasks
        assert mgr2.tasks["job"].steps[0].status == StepStatus.DONE
        assert mgr2.get_resume_point("job") == "b"
    finally:
        os.unlink(path)


# ===== Agent Memory =====

def test_memory_remember_recall():
    mem = AgentMemory()
    mem.remember("preference", "Formal tone preferred", tags=["communication"])
    results = mem.recall("preference")
    assert len(results) == 1
    assert "Formal" in results[0].content


def test_memory_recall_by_tags():
    mem = AgentMemory()
    mem.remember("preference", "Use metric units", tags=["formatting"])
    mem.remember("preference", "Formal tone", tags=["communication"])
    results = mem.recall(tags=["communication"])
    assert len(results) == 1
    assert "Formal" in results[0].content


def test_memory_recall_by_search():
    mem = AgentMemory()
    mem.remember("learning", "API X is slow on Mondays")
    mem.remember("learning", "Customer Y prefers phone calls")
    results = mem.recall(search="slow")
    assert len(results) == 1
    assert "API X" in results[0].content


def test_memory_forget():
    mem = AgentMemory()
    entry = mem.remember("context", "temp info")
    mem.forget(entry.id)
    results = mem.recall("context")
    assert len(results) == 0


def test_memory_update():
    mem = AgentMemory()
    entry = mem.remember("learning", "Initial version", data={"version": 1})
    mem.update(entry.id, content="Updated version", data={"version": 2})
    results = mem.recall("learning")
    assert "Updated" in results[0].content
    assert results[0].data["version"] == 2


def test_memory_persistence():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        mem = AgentMemory(persist_path=path)
        mem.remember("preference", "Dark mode", tags=["ui"])
        mem.add_rule("no_spam", "must", "Never send unsolicited emails", category="communication")

        mem2 = AgentMemory(persist_path=path)
        mem2.load()
        assert len(mem2.recall("preference")) == 1
        assert len(mem2.get_rules()) == 1
    finally:
        os.unlink(path)


# ===== Owner Rules =====

def test_rule_add_and_get():
    mem = AgentMemory()
    mem.add_rule("max_discount", "must", "discount <= 0.20", category="pricing")
    rules = mem.get_rules("pricing")
    assert len(rules) == 1
    assert rules[0].name == "max_discount"
    assert rules[0].level == RuleLevel.MUST


def test_rule_check_violation():
    mem = AgentMemory()
    mem.add_rule("max_discount", "must", "discount <= 0.20", category="pricing")
    violations = mem.check_rules("pricing", context={"discount": 0.25})
    assert len(violations) == 1
    assert "max_discount" in str(violations[0])


def test_rule_check_pass():
    mem = AgentMemory()
    mem.add_rule("max_discount", "must", "discount <= 0.20", category="pricing")
    violations = mem.check_rules("pricing", context={"discount": 0.15})
    assert len(violations) == 0


def test_rule_check_multiple():
    mem = AgentMemory()
    mem.add_rule("max_discount", "must", "discount <= 0.20", category="pricing")
    mem.add_rule("min_price", "must", "price >= 10", category="pricing")
    violations = mem.check_rules("pricing", context={"discount": 0.25, "price": 5})
    assert len(violations) == 2


def test_rule_remove():
    mem = AgentMemory()
    mem.add_rule("old_rule", "should", "something", category="test")
    mem.remove_rule("old_rule")
    assert len(mem.get_rules()) == 0


def test_rule_levels():
    mem = AgentMemory()
    mem.add_rule("r1", "must", "Hard rule", category="a")
    mem.add_rule("r2", "should", "Soft rule", category="a")
    mem.add_rule("r3", "avoid", "Avoid this", category="a")
    mem.add_rule("r4", "prefer", "Prefer this", category="a")
    assert len(mem.get_rules(level="must")) == 1
    assert len(mem.get_rules(level="should")) == 1


# ===== Integration: Builtins in engine =====

def test_engine_progress_builtins():
    engine = SyntecniaEngine()
    result = engine.run_source("""
let job be create_progress("sync", ["fetch", "validate", "save"])
start_step("sync", "fetch")
complete_step("sync", "fetch", "got 50 items")
start_step("sync", "validate")
complete_step("sync", "validate")
print(progress_display("sync"))
print(text(progress_percent("sync")))
""")
    assert result.success, f"Errors: {result.errors}"
    # Should show progress display with OK markers
    assert any("OK" in line for line in result.output)


def test_engine_resume_point():
    engine = SyntecniaEngine()
    result = engine.run_source("""
create_progress("job", ["a", "b", "c"])
start_step("job", "a")
complete_step("job", "a")
let next be resume_point("job")
print(next)
""")
    assert result.success
    assert "b" in result.output


def test_engine_memory_builtins():
    engine = SyntecniaEngine()
    result = engine.run_source("""
remember("preference", "Always use formal tone", ["communication"])
remember("learning", "API is slow on Mondays", ["api", "performance"])
let prefs be recall("preference")
print(text(length(prefs)))
let api_stuff be recall("learning", ["api"])
print(text(length(api_stuff)))
""")
    assert result.success
    assert result.output == ["1", "1"]


def test_engine_rules_builtins():
    engine = SyntecniaEngine()
    result = engine.run_source("""
add_rule("max_discount", "must", "discount <= 0.20", "pricing")
let violations be check_rules("pricing", {"discount": 0.25})
print(text(length(violations)))
let ok be check_rules("pricing", {"discount": 0.10})
print(text(length(ok)))
""")
    assert result.success
    assert result.output == ["1", "0"]


def test_engine_memory_summary():
    engine = SyntecniaEngine()
    result = engine.run_source("""
remember("preference", "Dark mode")
add_rule("formal", "should", "Use formal tone", "communication")
print(memory_summary())
""")
    assert result.success
    assert any("Agent Memory" in line for line in result.output)


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

"""Tests for error reporter, recovery protocol, and escalation."""
import sys
import time
sys.path.insert(0, "/root/Synsema")

from synsema.runtime.error_reporter import (
    ErrorReporter, ErrorDiagnostic, classify_error, CallFrame,
)
from synsema.runtime.recovery import (
    RecoveryProtocol, RecoveryResult, EscalationOption, HumanDecision,
)
from synsema.runtime.engine import SynsemaEngine
from synsema.core.interpreter import Environment
from synsema.core.types import syn_number, syn_text
from synsema.human.interaction import InteractionManager, AutoHandler


# ===== Error Reporter =====

def test_classify_division_by_zero():
    result = classify_error("Division by zero")
    assert result["category"] == "data"
    assert result["recoverable"] is True
    assert len(result["suggestions"]) > 0


def test_classify_undefined_variable():
    result = classify_error("Undefined variable: 'foo'")
    assert result["category"] == "logic"
    assert result["recoverable"] is False


def test_classify_capability():
    result = classify_error("Capability not granted: net(evil.com)")
    assert result["category"] == "capability"


def test_classify_http_error():
    result = classify_error("HTTP 500 from api.example.com")
    assert result["category"] == "io"
    assert result["retry_makes_sense"] is True


def test_classify_timeout():
    result = classify_error("Timed out after 30s")
    assert result["category"] == "io"
    assert result["retry_makes_sense"] is True


def test_classify_file_not_found():
    result = classify_error("File not found: /data/report.csv")
    assert result["category"] == "io"
    assert result["recoverable"] is True


def test_classify_invariant():
    result = classify_error("Invariant violation: x > 0")
    assert result["category"] == "logic"


def test_classify_map_key():
    result = classify_error("Map has no key 'email'")
    assert result["category"] == "data"


def test_error_reporter_build_diagnostic():
    reporter = ErrorReporter()
    reporter.load_source("test.syn", "let x be 0\nlet y be 10 / x\nprint(y)")

    class FakeError(Exception):
        pass
    err = FakeError("Division by zero")

    from synsema.core.tokens import SourceLocation
    err.location = SourceLocation(file="test.syn", line=2, column=15, offset=20)

    env = Environment(name="test")
    env.set("x", syn_number(0))
    env.set("y", syn_text("undefined"))

    diag = reporter.build_diagnostic(err, env, err.location)
    assert diag.file == "test.syn"
    assert diag.line == 2
    assert len(diag.source_context) > 0
    assert "x" in diag.visible_variables
    assert "0" in diag.visible_variables["x"]


def test_error_reporter_human_format():
    reporter = ErrorReporter()
    reporter.load_source("test.syn", "line1\nline2\nline3\nline4\nline5")
    reporter.set_intent("Process orders")

    from synsema.core.tokens import SourceLocation
    err = Exception("Division by zero")
    err.location = SourceLocation(file="test.syn", line=3, column=5, offset=0)

    diag = reporter.build_diagnostic(err)
    text = diag.format_human()
    assert "Division by zero" in text
    assert "Process orders" in text
    assert "Suggestions:" in text


def test_error_reporter_agent_format():
    reporter = ErrorReporter()
    err = Exception("HTTP 500 error")
    diag = reporter.build_diagnostic(err)
    data = diag.format_agent()
    assert data["error_type"] == "Exception"
    assert data["error_category"] == "io"
    assert data["retry_makes_sense"] is True


# ===== Recovery Protocol =====

def test_recovery_retry_succeeds():
    protocol = RecoveryProtocol()
    protocol.max_retry_attempts = 2
    protocol.retry_backoff_ms = [0, 0]  # no delay in tests
    output = []
    protocol.output_callback = lambda t: output.append(t)

    call_count = [0]
    def flaky_fn():
        call_count[0] += 1
        if call_count[0] < 2:
            raise Exception("Temporary failure")
        return syn_text("success!")

    err = Exception("Temporary failure")
    err.location = None
    result = protocol.handle_error(
        err, retry_fn=flaky_fn
    )
    assert result.recovered
    assert result.strategy_used == "retry"
    assert str(result.value) == "success!"


def test_recovery_fallback():
    protocol = RecoveryProtocol()
    output = []
    protocol.output_callback = lambda t: output.append(t)

    err = Exception("Service unavailable")
    result = protocol.handle_error(
        err, fallback_value=syn_text("default_data")
    )
    assert result.recovered
    assert result.strategy_used == "fallback"
    assert str(result.value) == "default_data"


def test_recovery_partial():
    protocol = RecoveryProtocol()
    output = []
    protocol.output_callback = lambda t: output.append(t)

    def partial_fn():
        from synsema.core.types import syn_list
        return syn_list([syn_text("partial_result")])

    err = Exception("Full data unavailable")
    result = protocol.handle_error(err, partial_fn=partial_fn)
    assert result.recovered
    assert result.strategy_used == "partial"


def test_recovery_speculate():
    protocol = RecoveryProtocol()
    output = []
    protocol.output_callback = lambda t: output.append(t)

    def alt_a():
        raise Exception("A also fails")
    def alt_b():
        return syn_text("B worked!")

    err = Exception("Primary approach failed")
    result = protocol.handle_error(
        err, speculate_fns=[alt_a, alt_b]
    )
    assert result.recovered
    assert "speculate:1" in result.strategy_used
    assert str(result.value) == "B worked!"


def test_recovery_all_fail_escalates():
    protocol = RecoveryProtocol()
    protocol.max_retry_attempts = 1
    protocol.retry_backoff_ms = [0]
    output = []
    protocol.output_callback = lambda t: output.append(t)

    # Provide a human callback that auto-responds
    protocol.human_callback = lambda action, msg: "A"

    def always_fails():
        raise Exception("still broken")

    err = Exception("Persistent failure")
    result = protocol.handle_error(
        err,
        retry_fn=always_fails,
        speculate_fns=[always_fails],
        context="processing orders",
    )
    assert result.escalated
    assert result.human_decision is not None
    assert result.human_decision.chosen_option == "A"


def test_recovery_precedent_lookup():
    protocol = RecoveryProtocol()
    protocol.decision_log.append(HumanDecision(
        timestamp=time.time(),
        error_type="RuntimeError",
        error_message="API timeout",
        context="sync_inventory",
        options_presented=["A: Retry", "B: Skip"],
        chosen_option="B",
        chosen_label="Skip",
        outcome="worked fine",
    ))

    precedent = protocol.find_precedent("RuntimeError", "inventory")
    assert precedent is not None
    assert precedent.chosen_option == "B"


def test_recovery_no_precedent():
    protocol = RecoveryProtocol()
    precedent = protocol.find_precedent("UnknownError")
    assert precedent is None


def test_recovery_decision_persistence(tmp_path=None):
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        protocol = RecoveryProtocol()
        protocol.decision_log.append(HumanDecision(
            timestamp=time.time(),
            error_type="TestError",
            error_message="test msg",
            context="test",
            options_presented=["A: Do it"],
            chosen_option="A",
            chosen_label="Do it",
        ))
        protocol.save_decisions(path)

        protocol2 = RecoveryProtocol()
        protocol2.load_decisions(path)
        assert len(protocol2.decision_log) == 1
        assert protocol2.decision_log[0].error_type == "TestError"
    finally:
        os.unlink(path)


# ===== Integration: Rich diagnostics in engine =====

def test_engine_rich_diagnostic_on_error():
    engine = SynsemaEngine()
    result = engine.run_source("""
let x be 0
let y be 10 / x
""")
    assert not result.success
    assert len(result.diagnostics) > 0
    diag = result.diagnostics[0]
    assert diag.error_category == "data"
    assert diag.recoverable is True
    assert len(diag.suggestions) > 0


def test_engine_rich_diagnostic_undefined_var():
    engine = SynsemaEngine()
    result = engine.run_source("print(unknown_var)")
    assert not result.success
    assert len(result.diagnostics) > 0
    diag = result.diagnostics[0]
    assert diag.error_category == "logic"


def test_engine_rich_diagnostic_with_intent():
    engine = SynsemaEngine()
    result = engine.run_source("""
intent: "Calculate payroll"
let salary be 5000
let hours be 0
let rate be salary / hours
""")
    assert not result.success
    assert len(result.diagnostics) > 0
    diag = result.diagnostics[0]
    assert diag.active_intent == "Calculate payroll"


def test_engine_diagnostic_shows_variables():
    engine = SynsemaEngine()
    result = engine.run_source("""
let name be "Alice"
let balance be 100
let items be [1, 2, 3]
let bad be 10 / 0
""")
    assert not result.success
    diag = result.diagnostics[0]
    # Variables should include user-defined ones
    assert "name" in diag.visible_variables
    assert "Alice" in diag.visible_variables["name"]


def test_engine_diagnostic_format_agent():
    engine = SynsemaEngine()
    result = engine.run_source("let x be 1 / 0")
    assert not result.success
    diag = result.diagnostics[0]
    agent_data = diag.format_agent()
    assert isinstance(agent_data, dict)
    assert "suggestions" in agent_data
    assert "error_category" in agent_data
    assert agent_data["recoverable"] is True


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

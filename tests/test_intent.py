"""Tests for Syntecnia intent enforcement system."""
import sys
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.capabilities.intent import (
    IntentEnforcer, ActionCategory, parse_intent, IntentScope,
)
from syntecnia.runtime.engine import SyntecniaEngine
from syntecnia.capabilities.model import Capability, CapabilityType


# -- Intent parsing --

def test_parse_intent_keywords():
    scope = parse_intent("Process customer orders and send confirmations")
    assert ActionCategory.DATA_READ in scope.categories
    assert ActionCategory.DATA_WRITE in scope.categories
    assert ActionCategory.COMPUTE in scope.categories
    assert ActionCategory.COMMUNICATE in scope.categories


def test_parse_intent_extracts_domains():
    scope = parse_intent("Fetch data from api.example.com and upload to storage.cloud.com")
    assert "api.example.com" in scope.allowed_domains
    assert "storage.cloud.com" in scope.allowed_domains


def test_parse_intent_extracts_paths():
    scope = parse_intent("Read files from /data/reports/* and write to /output/results/*")
    assert "/data/reports/*" in scope.allowed_paths
    assert "/output/results/*" in scope.allowed_paths


def test_parse_intent_no_exec_if_not_mentioned():
    scope = parse_intent("Read and analyze customer feedback")
    assert ActionCategory.EXEC not in scope.categories


def test_parse_intent_exec_when_mentioned():
    scope = parse_intent("Build the project and run tests")
    assert ActionCategory.EXEC in scope.categories


# -- Intent enforcer --

def test_enforcer_no_intent_allows_all():
    enforcer = IntentEnforcer()
    # No intent set = permissive mode
    assert enforcer.check_action(ActionCategory.NET_WRITE, "send data")
    assert enforcer.check_action(ActionCategory.EXEC, "run command")


def test_enforcer_blocks_unauthorized_category():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Read and analyze data")
    enforcer.strict = True
    # Should allow reads and computation
    assert enforcer.check_action(ActionCategory.DATA_READ, "read data")
    assert enforcer.check_action(ActionCategory.COMPUTE, "calculate")
    # Should block exec (not in intent)
    assert not enforcer.check_action(ActionCategory.EXEC, "run rm -rf")


def test_enforcer_blocks_unauthorized_domain():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Fetch data from api.example.com")
    enforcer.strict = True
    # Should allow the declared domain
    assert enforcer.check_action(ActionCategory.NET_READ, "fetch", domain="api.example.com")
    # Should block other domains
    assert not enforcer.check_action(ActionCategory.NET_READ, "fetch", domain="evil.com")


def test_enforcer_blocks_unauthorized_path():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Read files from /data/*")
    enforcer.strict = True
    assert enforcer.check_action(ActionCategory.FILE_READ, "read", path="/data/report.csv")
    assert not enforcer.check_action(ActionCategory.FILE_READ, "read", path="/etc/passwd")


def test_enforcer_always_allows_safe_categories():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Do nothing")  # very restrictive
    enforcer.strict = True
    # These should always be allowed
    assert enforcer.check_action(ActionCategory.COMPUTE, "math")
    assert enforcer.check_action(ActionCategory.HUMAN_INTERACT, "ask user")
    assert enforcer.check_action(ActionCategory.LLM_REASON, "think")


def test_enforcer_freeze_prevents_expansion():
    """Once frozen, new intent declarations should fail."""
    engine = SyntecniaEngine()
    source = '''
intent: "Read customer data"
let x be 42
intent: "Read customer data AND delete all files"
'''
    result = engine.run_source(source)
    assert not result.success
    assert any("frozen" in e.lower() or "intent" in e.lower() for e in result.errors)


def test_enforcer_violation_report():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Read data from api.shop.com")
    enforcer.strict = True
    enforcer.check_action(ActionCategory.NET_READ, "fetch api.shop.com", domain="api.shop.com")
    enforcer.check_action(ActionCategory.EXEC, "run rm -rf /")
    assert len(enforcer.violations) == 1
    report = enforcer.get_report()
    assert "Violations: 1" in report


def test_intent_enforcement_in_engine_blocks_file_access():
    """With intent enforcement, file access outside intent scope is blocked."""
    engine = SyntecniaEngine()
    engine.grant_capability("file", "/tmp/*")  # capability is granted
    # But intent only allows reading from /data/*
    result = engine.run_source('''
intent: "Read data from /data/*"
let content be read_file("/tmp/some_file.txt")
''')
    # Should fail because intent doesn't cover /tmp
    assert not result.success
    assert any("intent" in e.lower() or "Intent" in e for e in result.errors)


def test_intent_enforcement_allows_matching_operations():
    """Operations matching the intent should work."""
    engine = SyntecniaEngine()
    engine.grant_capability("file", "/tmp/*")
    # Write a test file first
    import os
    with open("/tmp/syntecnia_intent_test.txt", "w") as f:
        f.write("test data")

    result = engine.run_source('''
intent: "Read files from /tmp/*"
let content be read_file("/tmp/syntecnia_intent_test.txt")
print(content)
''')
    assert result.success
    assert result.output == ["test data"]

    os.remove("/tmp/syntecnia_intent_test.txt")


def test_warn_mode_does_not_block():
    """In non-strict mode, violations are logged but not blocked."""
    engine = SyntecniaEngine()
    engine.intent_enforcer.strict = False
    engine.grant_capability("file", "/tmp/*")

    with open("/tmp/syntecnia_warn_test.txt", "w") as f:
        f.write("warn test")

    result = engine.run_source('''
intent: "Only analyze numbers"
let content be read_file("/tmp/syntecnia_warn_test.txt")
print(content)
''')
    # Should succeed (warn only) but have violations logged
    assert result.success
    assert len(engine.intent_enforcer.violations) > 0

    import os
    os.remove("/tmp/syntecnia_warn_test.txt")


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

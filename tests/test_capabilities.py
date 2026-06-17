"""Tests for Syntecnia capability system."""
import sys
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.capabilities.model import (
    Capability, CapabilityType, CapabilitySet, CapabilityViolation,
    parse_capability,
)
from syntecnia.runtime.engine import SyntecniaEngine


def test_capability_creation():
    cap = parse_capability("net", "api.example.com")
    assert cap.type == CapabilityType.NET
    assert cap.scope == "api.example.com"


def test_capability_covers_exact():
    cap = Capability(CapabilityType.NET, "api.example.com")
    req = Capability(CapabilityType.NET, "api.example.com")
    assert cap.covers(req)


def test_capability_covers_wildcard():
    cap = Capability(CapabilityType.NET, "*.example.com")
    req = Capability(CapabilityType.NET, "api.example.com")
    assert cap.covers(req)


def test_capability_covers_none_scope():
    cap = Capability(CapabilityType.NET, None)
    req = Capability(CapabilityType.NET, "anything.com")
    assert cap.covers(req)


def test_capability_file_covers_read_write():
    cap = Capability(CapabilityType.FILE, "/data/*")
    read_req = Capability(CapabilityType.FILE_READ, "/data/report.csv")
    write_req = Capability(CapabilityType.FILE_WRITE, "/data/output.csv")
    assert cap.covers(read_req)
    assert cap.covers(write_req)


def test_capability_does_not_cover_different_type():
    cap = Capability(CapabilityType.NET, "example.com")
    req = Capability(CapabilityType.FILE, "example.com")
    assert not cap.covers(req)


def test_capability_set_grant_check():
    cs = CapabilitySet("test")
    cs.grant(Capability(CapabilityType.NET, "api.example.com"))
    assert cs.check(Capability(CapabilityType.NET, "api.example.com"))
    assert not cs.check(Capability(CapabilityType.NET, "evil.com"))


def test_capability_set_deny_overrides_grant():
    cs = CapabilitySet("test")
    cs.grant(Capability(CapabilityType.NET, "*.example.com"))
    cs.deny(Capability(CapabilityType.NET, "secret.example.com"))
    assert cs.check(Capability(CapabilityType.NET, "api.example.com"))
    assert not cs.check(Capability(CapabilityType.NET, "secret.example.com"))


def test_capability_set_parent_inheritance():
    parent = CapabilitySet("parent")
    parent.grant(Capability(CapabilityType.TIME))
    child = parent.create_child("child")
    assert child.check(Capability(CapabilityType.TIME))


def test_capability_sandbox_no_inheritance():
    parent = CapabilitySet("parent")
    parent.grant(Capability(CapabilityType.NET, None))
    sandbox = parent.create_sandbox("restricted")
    # Sandbox should NOT inherit parent capabilities
    assert not sandbox.check(Capability(CapabilityType.NET, "example.com"))


def test_capability_sandbox_explicit_grants():
    parent = CapabilitySet("parent")
    sandbox = parent.create_sandbox("restricted", [
        Capability(CapabilityType.STDOUT),
    ])
    assert sandbox.check(Capability(CapabilityType.STDOUT))
    assert not sandbox.check(Capability(CapabilityType.NET, "anything"))


def test_capability_audit_trail():
    cs = CapabilitySet("test")
    cs.grant(Capability(CapabilityType.NET, "example.com"))
    cs.check(Capability(CapabilityType.NET, "example.com"), source="test:1")
    cs.check(Capability(CapabilityType.NET, "evil.com"), source="test:2")
    assert len(cs.audit_log) == 2
    assert cs.audit_log[0].granted is True
    assert cs.audit_log[1].granted is False


def test_capability_violation_in_engine():
    """Test that secure builtins fail without capabilities."""
    engine = SyntecniaEngine(secure=True)
    # In secure mode, even stdout needs a capability
    # But the engine auto-grants stdout in non-secure mode
    engine.capabilities.grant(Capability(CapabilityType.STDOUT))

    # Try to read a file without file capability
    result = engine.run_source('let content be read_file("/etc/hostname")')
    assert not result.success
    assert any("Capability" in e or "capability" in e.lower() for e in result.errors)


def test_capability_grant_enables_operation():
    """Test that granting capability allows the operation."""
    engine = SyntecniaEngine()
    engine.grant_capability("file", "/tmp/*")
    # This should work now
    result = engine.run_source('write_file("/tmp/syntecnia_test.txt", "hello")')
    assert result.success

    # Read it back
    result2 = engine.run_source('let c be read_file("/tmp/syntecnia_test.txt")\nprint(c)')
    assert result2.success
    assert result2.output == ["hello"]

    # Cleanup
    import os
    try:
        os.remove("/tmp/syntecnia_test.txt")
    except:
        pass


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

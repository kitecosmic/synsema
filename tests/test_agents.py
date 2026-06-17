"""Tests for Syntecnia agent swarm and blackboard."""
import sys
import time
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.agents.blackboard import Blackboard
from syntecnia.agents.swarm import AgentSwarm, AgentState
from syntecnia.core.types import syn_text, syn_number, syn_list, syn_nothing
from syntecnia.human.interaction import (
    InteractionManager, AutoHandler, QueueHandler,
    InteractionType, InteractionStatus,
)
from syntecnia.llm.provider import MockProvider, create_provider


# -- Blackboard tests --

def test_blackboard_write_read():
    bb = Blackboard()
    bb.write("key1", syn_text("hello"), agent="agent1")
    val = bb.read("key1", agent="agent2")
    assert val is not None
    assert val.raw == "hello"


def test_blackboard_read_nonexistent():
    bb = Blackboard()
    val = bb.read("nonexistent")
    assert val is None


def test_blackboard_versioning():
    bb = Blackboard()
    bb.write("counter", syn_number(1), agent="a1")
    bb.write("counter", syn_number(2), agent="a1")
    bb.write("counter", syn_number(3), agent="a2")
    info = bb.get_entry_info("counter")
    assert info["version"] == 3
    assert info["history_length"] == 2  # two previous values


def test_blackboard_watcher():
    bb = Blackboard()
    received = []
    bb.watch("events", lambda k, v, a: received.append((k, str(v), a)))
    bb.write("events", syn_text("event1"), agent="producer")
    bb.write("events", syn_text("event2"), agent="producer")
    assert len(received) == 2
    assert received[0] == ("events", "event1", "producer")


def test_blackboard_snapshot():
    bb = Blackboard()
    bb.write("a", syn_number(1))
    bb.write("b", syn_number(2))
    snap = bb.snapshot()
    assert len(snap) == 2
    assert snap["a"].raw == 1
    assert snap["b"].raw == 2


def test_blackboard_delete():
    bb = Blackboard()
    bb.write("temp", syn_text("data"))
    bb.delete("temp")
    assert bb.read("temp") is None


def test_blackboard_events():
    bb = Blackboard()
    bb.write("x", syn_number(1), agent="a1")
    bb.read("x", agent="a2")
    events = bb.get_events()
    assert len(events) == 2
    assert events[0].event_type == "write"
    assert events[1].event_type == "read"


# -- Human interaction tests --

def test_auto_handler_approve():
    mgr = InteractionManager(AutoHandler(default_approve=True))
    cb = mgr.get_callback()
    result = cb("approve", "Do this?")
    assert result is True


def test_auto_handler_deny():
    mgr = InteractionManager(AutoHandler(default_approve=False))
    cb = mgr.get_callback()
    result = cb("approve", "Do this?")
    assert result is False


def test_auto_handler_ask():
    mgr = InteractionManager(AutoHandler(default_answer="test_answer"))
    cb = mgr.get_callback()
    result = cb("ask", "What?")
    assert result == "test_answer"


def test_auto_handler_history():
    handler = AutoHandler()
    mgr = InteractionManager(handler)
    cb = mgr.get_callback()
    cb("approve", "First")
    cb("confirm", "Second")
    cb("ask", "Third")
    assert len(mgr.history) == 3
    assert len(handler.log) == 3


def test_queue_handler_respond():
    handler = QueueHandler()
    import threading

    result_holder = [None]

    def make_request():
        from syntecnia.human.interaction import InteractionRequest, InteractionType
        req = InteractionRequest(id="req_1", type=InteractionType.APPROVE, message="Test?")
        result_holder[0] = handler.handle(req)

    t = threading.Thread(target=make_request)
    t.start()
    time.sleep(0.1)  # let thread start

    # Respond from "outside"
    pending = handler.get_pending()
    assert len(pending) == 1
    handler.respond("req_1", True, approved=True)
    t.join(timeout=2)

    assert result_holder[0] is not None
    assert result_holder[0].status == InteractionStatus.APPROVED


# -- LLM provider tests --

def test_mock_provider():
    provider = MockProvider(responses={
        "reason": "This is a mock reasoning result",
        "decide": "option_a",
    })
    from syntecnia.llm.provider import LLMRequest
    resp = provider.call(LLMRequest(operation="reason", data={"subject": "test"}))
    assert resp.content == "This is a mock reasoning result"
    assert len(provider.call_log) == 1


def test_mock_provider_in_engine():
    from syntecnia.runtime.engine import SyntecniaEngine
    engine = SyntecniaEngine()
    engine.configure_llm_provider("mock", responses={
        "analyze": "Positive sentiment",
        "decide": "refund",
    })

    source = '''
let data be {"issue": "broken item"}
let result be analyze data for "sentiment"
print(result)
'''
    result = engine.run_source(source)
    assert result.success
    assert "Positive sentiment" in result.output[0]


def test_create_provider_factory():
    p = create_provider("mock")
    assert p.name() == "mock"
    p2 = create_provider("anthropic")
    assert "anthropic" in p2.name()


# -- Integration: human + engine --

def test_human_interaction_in_engine():
    from syntecnia.runtime.engine import SyntecniaEngine
    engine = SyntecniaEngine()

    mgr = InteractionManager(AutoHandler(default_approve=True))
    engine.configure_human(mgr.get_callback())

    source = '''
approve "Deploy to production?"
print("deployed!")
'''
    result = engine.run_source(source)
    assert result.success
    assert "deployed!" in result.output


def test_human_denial_in_engine():
    from syntecnia.runtime.engine import SyntecniaEngine
    engine = SyntecniaEngine()

    mgr = InteractionManager(AutoHandler(default_approve=False))
    engine.configure_human(mgr.get_callback())

    source = '''
let approved be approve "Do dangerous thing?"
when approved
    print("did it")
otherwise
    print("denied")
'''
    result = engine.run_source(source)
    assert result.success
    assert "denied" in result.output


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

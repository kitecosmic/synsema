"""Tests for REAL agent concurrency — threads, blackboard, signals."""
import sys
import time
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.runtime.engine import SyntecniaEngine
from syntecnia.agents.swarm import AgentState


def test_agent_define_does_not_execute():
    """Agent body should NOT run on definition — only on spawn."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Worker
    print("I am running!")

print("After definition")
""")
    assert result.success, f"Errors: {result.errors}"
    # "I am running!" should NOT appear — agent was defined but not spawned
    assert result.output == ["After definition"], f"Got: {result.output}"


def test_spawn_runs_agent_body():
    """Spawn should actually execute the agent body."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Greeter
    share "hello from agent" as "greeting"

spawn Greeter
""")
    assert result.success, f"Errors: {result.errors}"
    # Give the thread a moment to run
    time.sleep(0.2)
    # Check the blackboard has the value
    val = engine.swarm.blackboard.read("greeting")
    assert val is not None, "Agent didn't write to blackboard"
    assert val.raw == "hello from agent"


def test_spawn_with_arguments():
    """Spawn passes arguments to the agent."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Calculator
    let result be x * 2
    share result as "calc_result"

spawn Calculator with x = 21
""")
    assert result.success, f"Errors: {result.errors}"
    time.sleep(0.2)
    val = engine.swarm.blackboard.read("calc_result")
    assert val is not None, "Agent didn't write result"
    assert val.raw == 42


def test_two_agents_communicate_via_blackboard():
    """Two agents running concurrently, sharing data via blackboard."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Producer
    share "data_from_producer" as "shared_data"
    signal "data_ready"

agent Consumer
    wait_for "data_ready"
    observe "shared_data" as data
    share data as "consumed"

spawn Producer
spawn Consumer
""")
    assert result.success, f"Errors: {result.errors}"
    # Wait for both agents
    engine.swarm.wait_all(timeout=5)
    time.sleep(0.3)

    # Producer should have written
    produced = engine.swarm.blackboard.read("shared_data")
    assert produced is not None, "Producer didn't write"
    assert produced.raw == "data_from_producer"

    # Consumer should have consumed
    consumed = engine.swarm.blackboard.read("consumed")
    assert consumed is not None, "Consumer didn't consume"
    assert consumed.raw == "data_from_producer"


def test_signal_wakes_waiting_agent():
    """signal/wait_for actually blocks and wakes up."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Sender
    share "preparing" as "status"
    signal "ready"

agent Receiver
    wait_for "ready"
    share "received" as "status"

spawn Receiver
spawn Sender
""")
    assert result.success, f"Errors: {result.errors}"
    engine.swarm.wait_all(timeout=5)
    time.sleep(0.3)

    status = engine.swarm.blackboard.read("status")
    assert status is not None
    # The last write wins — Receiver writes "received" after Sender writes "preparing"
    assert status.raw == "received", f"Got: {status.raw}"


def test_main_shares_agent_observes():
    """Main program shares data, spawned agent observes it."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
share "hello from main" as "main_data"

agent Reader
    observe "main_data" as data
    share data as "agent_read"

spawn Reader
""")
    assert result.success, f"Errors: {result.errors}"
    time.sleep(0.3)

    val = engine.swarm.blackboard.read("agent_read")
    assert val is not None, "Agent didn't read from blackboard"
    assert val.raw == "hello from main"


def test_spawn_undefined_agent_fails():
    """Spawning an agent that doesn't exist should error."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
spawn NonExistent
""")
    assert not result.success
    assert any("No agent defined" in e or "NonExistent" in e for e in result.errors)


def test_swarm_dashboard_shows_agents():
    """The swarm dashboard should reflect spawned agents."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Worker
    share "done" as "status"

spawn Worker
""")
    assert result.success
    time.sleep(0.3)

    dashboard = engine.swarm.dashboard()
    assert dashboard["total_agents"] >= 1
    agent_names = list(dashboard["agents"].keys())
    assert any("Worker" in name for name in agent_names)


def test_multiple_spawns_of_same_agent():
    """Spawn the same agent type multiple times — each runs independently."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Adder
    let result be n + 100
    share result as "sum"

spawn Adder with n = 1
spawn Adder with n = 2
spawn Adder with n = 3
""")
    assert result.success
    engine.swarm.wait_all(timeout=5)
    time.sleep(0.3)

    # All three wrote to "sum" — last one wins, but all ran
    val = engine.swarm.blackboard.read("sum")
    assert val is not None, "No agent wrote to blackboard"
    # Value should be one of 101, 102, 103
    assert val.raw in (101, 102, 103), f"Unexpected value: {val.raw}"
    # Dashboard should show 3 agents
    dashboard = engine.swarm.dashboard()
    assert dashboard["total_agents"] == 3


def test_agent_error_captured_in_swarm():
    """Agent errors should be captured, not crash the program."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
agent Crasher
    let x be 1 / 0

spawn Crasher
""")
    assert result.success  # main program succeeds even if agent crashes
    time.sleep(0.3)

    dashboard = engine.swarm.dashboard()
    agent_names = list(dashboard["agents"].keys())
    crasher = [n for n in agent_names if "Crasher" in n]
    assert len(crasher) > 0
    assert dashboard["agents"][crasher[0]]["state"] == "ERROR"


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

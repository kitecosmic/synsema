"""
Syntecnia Agent Swarm — Multi-agent runtime.

The swarm manages multiple agents running concurrently.
Each agent:
    - Has its own execution environment
    - Has its own capability set (sandboxed)
    - Communicates via the blackboard
    - Has observable state (idle, working, waiting, done, error)
    - Can signal other agents

The swarm provides:
    - Agent lifecycle management (spawn, stop, status)
    - The shared blackboard
    - A signal bus for inter-agent communication
    - A dashboard view of all agents' states
    - Conflict detection (two agents touching the same resource)

Think of it as the beehive: each bee (agent) works independently,
but they coordinate through shared signals (pheromones/blackboard).
"""

import threading
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from ..core.types import SynValue, syn_nothing, syn_text, syn_map
from ..core.interpreter import Interpreter, Environment
from ..capabilities.model import CapabilitySet, Capability
from .blackboard import Blackboard


class AgentState(Enum):
    IDLE = auto()
    STARTING = auto()
    WORKING = auto()
    WAITING = auto()
    DONE = auto()
    ERROR = auto()
    STOPPED = auto()


@dataclass
class AgentInfo:
    """Observable info about a running agent."""
    name: str
    state: AgentState = AgentState.IDLE
    current_task: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    error: Optional[str] = None
    resources_in_use: List[str] = field(default_factory=list)
    signals_sent: List[str] = field(default_factory=list)
    signals_received: List[str] = field(default_factory=list)


@dataclass
class Signal:
    """Inter-agent signal."""
    name: str
    sender: str
    data: Optional[SynValue] = None
    timestamp: float = 0.0


class AgentSwarm:
    """
    Manages a swarm of concurrent agents.

    Usage:
        swarm = AgentSwarm()
        swarm.define_agent("researcher", researcher_body, capabilities)
        swarm.define_agent("writer", writer_body, capabilities)
        swarm.spawn("researcher", {"query": syn_text("AI safety")})
        swarm.spawn("writer")
        swarm.wait_all()
        dashboard = swarm.dashboard()
    """

    def __init__(self):
        self.blackboard = Blackboard()
        self.agents: Dict[str, AgentInfo] = {}
        self.agent_definitions: Dict[str, Dict] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.RLock()
        self._signals: Dict[str, List[Signal]] = {}  # signal_name → pending queue
        self._signal_history: List[Signal] = []       # consumed signals (for dashboard)
        self._signal_events: Dict[str, threading.Event] = {}
        self._interpreters: Dict[str, Interpreter] = {}

    def define_agent(self, name: str, body: list, capabilities: CapabilitySet = None,
                     task_registry: Dict = None):
        """
        Define an agent type (doesn't start it yet).

        body: list of AST nodes to execute
        capabilities: what this agent is allowed to do
        task_registry: tasks available to this agent
        """
        self.agent_definitions[name] = {
            "body": body,
            "capabilities": capabilities or CapabilitySet(name=f"agent:{name}"),
            "tasks": task_registry or {},
        }

    def register_agent(self, instance_id: str, info: AgentInfo,
                       thread: threading.Thread):
        """
        Register a spawned agent. The actual spawn logic lives in
        engine._wire_swarm.swarm_spawn, which creates the interpreter,
        wires blackboard/signals, and starts the thread. This method
        just registers the result for dashboard/tracking.
        """
        with self._lock:
            self.agents[instance_id] = info
            self._threads[instance_id] = thread

    def stop(self, instance_id: str):
        """Request an agent to stop."""
        with self._lock:
            if instance_id in self.agents:
                self.agents[instance_id].state = AgentState.STOPPED

    def signal(self, signal_name: str, sender: str, data: SynValue = None):
        """
        Send a signal that waiting agents can consume.

        Signals are queued, not latched. Each wait_for consumes one signal.
        Multiple signals with the same name queue up.
        """
        sig = Signal(
            name=signal_name,
            sender=sender,
            data=data,
            timestamp=time.time(),
        )
        with self._lock:
            if signal_name not in self._signals:
                self._signals[signal_name] = []
            self._signals[signal_name].append(sig)

            # Wake up anyone waiting for this signal
            if signal_name not in self._signal_events:
                self._signal_events[signal_name] = threading.Event()
            self._signal_events[signal_name].set()

    def wait_for_signal(self, signal_name: str, timeout: float = None) -> Optional[Signal]:
        """
        Wait for and CONSUME one signal. Returns it and removes from queue.

        If a signal is already queued, returns immediately (consumes it).
        If no signal, polls with short sleeps. Each cycle checks:
        - Did the signal arrive?
        - Are all agents dead/done? If so, no one can emit → return None.
        """
        poll_interval = 0.1  # 100ms
        deadline = time.time() + (timeout or 30)

        while time.time() < deadline:
            with self._lock:
                # Check if signal queued
                if signal_name in self._signals and self._signals[signal_name]:
                    sig = self._signals[signal_name].pop(0)
                    self._signal_history.append(sig)
                    if not self._signals[signal_name] and signal_name in self._signal_events:
                        self._signal_events[signal_name].clear()
                    return sig

                # Check if any agent is still alive and could emit
                alive = any(
                    a.state in (AgentState.STARTING, AgentState.WORKING, AgentState.WAITING)
                    for a in self.agents.values()
                )
                if not alive and self.agents:
                    # All agents are done/error/stopped — no one will emit
                    return None

            # Prepare event for this signal
            with self._lock:
                if signal_name not in self._signal_events:
                    self._signal_events[signal_name] = threading.Event()
                self._signal_events[signal_name].clear()
                event = self._signal_events[signal_name]

            # Wait for a short interval
            remaining = min(poll_interval, deadline - time.time())
            if remaining <= 0:
                break
            event.wait(timeout=remaining)

        return None

    def wait_all(self, timeout: float = 60):
        """Wait for all agents to finish."""
        deadline = time.time() + timeout
        for name, thread in self._threads.items():
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)

    def dashboard(self) -> Dict[str, Any]:
        """
        Get a real-time view of all agents and the blackboard.

        This is the "hive mind view" — you can see:
        - Every agent's state
        - What each agent is doing
        - The shared blackboard state
        - Recent signals
        - Potential conflicts
        """
        with self._lock:
            agents_view = {}
            for name, info in self.agents.items():
                duration = 0
                if info.started_at:
                    end = info.finished_at or time.time()
                    duration = end - info.started_at
                agents_view[name] = {
                    "state": info.state.name,
                    "task": info.current_task,
                    "duration_s": round(duration, 2),
                    "error": info.error,
                    "resources": info.resources_in_use,
                }

            blackboard_view = {}
            for key, entry in self.blackboard._data.items():
                blackboard_view[key] = {
                    "value": str(entry.value),
                    "version": entry.version,
                    "written_by": entry.written_by,
                }

            # Show both pending and consumed signals
            signals_view = {}
            # Pending (not yet consumed)
            for sig_name, sigs in self._signals.items():
                if sigs:
                    signals_view[sig_name] = [{
                        "sender": s.sender,
                        "data": str(s.data) if s.data else None,
                        "status": "pending",
                    } for s in sigs[-5:]]
            # History (consumed)
            for sig in self._signal_history[-20:]:
                if sig.name not in signals_view:
                    signals_view[sig.name] = []
                signals_view[sig.name].append({
                    "sender": sig.sender,
                    "data": str(sig.data) if sig.data else None,
                    "status": "consumed",
                })

            # Detect conflicts: multiple agents writing to same blackboard keys
            conflicts = self._detect_conflicts()

            return {
                "agents": agents_view,
                "blackboard": blackboard_view,
                "signals": signals_view,
                "conflicts": conflicts,
                "total_agents": len(self.agents),
                "active": sum(1 for a in self.agents.values() if a.state == AgentState.WORKING),
            }

    def _detect_conflicts(self) -> List[Dict]:
        """Detect when multiple agents write to the same key."""
        conflicts = []
        events = self.blackboard.get_events()
        writes_by_key: Dict[str, set] = {}

        for event in events:
            if event.event_type == "write":
                if event.key not in writes_by_key:
                    writes_by_key[event.key] = set()
                writes_by_key[event.key].add(event.agent)

        for key, agents in writes_by_key.items():
            if len(agents) > 1:
                conflicts.append({
                    "key": key,
                    "agents": list(agents),
                    "type": "concurrent_write",
                })

        return conflicts

    def format_dashboard(self) -> str:
        """Format dashboard as readable text."""
        d = self.dashboard()
        lines = []
        lines.append(f"=== Swarm Dashboard ({d['total_agents']} agents, {d['active']} active) ===\n")

        lines.append("Agents:")
        for name, info in d["agents"].items():
            state = info["state"]
            duration = info["duration_s"]
            error = f" ERROR: {info['error']}" if info["error"] else ""
            lines.append(f"  [{state:8s}] {name} ({duration}s){error}")

        if d["blackboard"]:
            lines.append("\nBlackboard:")
            for key, info in d["blackboard"].items():
                lines.append(f"  {key} = {info['value']} (v{info['version']}, by {info['written_by']})")

        if d["signals"]:
            lines.append("\nSignals:")
            for sig_name, sigs in d["signals"].items():
                for s in sigs:
                    lines.append(f"  {sig_name} from {s['sender']}")

        if d["conflicts"]:
            lines.append("\nCONFLICTS:")
            for c in d["conflicts"]:
                lines.append(f"  Key '{c['key']}' written by: {', '.join(c['agents'])}")

        return "\n".join(lines)

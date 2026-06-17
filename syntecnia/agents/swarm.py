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
        self._signals: Dict[str, List[Signal]] = {}  # signal_name → list
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

    def spawn(self, agent_name: str, args: Dict[str, SynValue] = None,
              instance_name: str = None) -> str:
        """
        Spawn an agent instance.

        Returns the instance ID.
        """
        definition = self.agent_definitions.get(agent_name)
        if not definition:
            raise ValueError(f"No agent definition found for '{agent_name}'")

        instance_id = instance_name or f"{agent_name}_{len(self.agents)}"

        info = AgentInfo(
            name=instance_id,
            state=AgentState.STARTING,
            started_at=time.time(),
        )

        with self._lock:
            self.agents[instance_id] = info

        # Create agent's interpreter with its own environment
        interpreter = Interpreter()
        interpreter.blackboard = self.blackboard._data  # share blackboard data

        # Wire blackboard operations
        original_share = interpreter.blackboard
        interpreter.blackboard = {}

        def agent_share(key, value):
            self.blackboard.write(key, value, agent=instance_id)

        def agent_observe(key):
            return self.blackboard.read(key, agent=instance_id)

        self._interpreters[instance_id] = interpreter

        # Set initial arguments
        if args:
            for k, v in args.items():
                interpreter.global_env.set(k, v)

        # Run in thread
        def run_agent():
            try:
                info.state = AgentState.WORKING
                for node in definition["body"]:
                    interpreter._exec(node, interpreter.global_env)
                info.state = AgentState.DONE
            except Exception as e:
                info.state = AgentState.ERROR
                info.error = str(e)
            finally:
                info.finished_at = time.time()

        thread = threading.Thread(target=run_agent, name=instance_id, daemon=True)
        self._threads[instance_id] = thread
        thread.start()

        return instance_id

    def stop(self, instance_id: str):
        """Request an agent to stop."""
        with self._lock:
            if instance_id in self.agents:
                self.agents[instance_id].state = AgentState.STOPPED

    def signal(self, signal_name: str, sender: str, data: SynValue = None):
        """Send a signal that any agent can receive."""
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
            if signal_name in self._signal_events:
                self._signal_events[signal_name].set()

    def wait_for_signal(self, signal_name: str, timeout: float = None) -> Optional[Signal]:
        """Wait for a signal. Returns the most recent one."""
        with self._lock:
            # Check if signal already exists
            if signal_name in self._signals and self._signals[signal_name]:
                return self._signals[signal_name][-1]
            if signal_name not in self._signal_events:
                self._signal_events[signal_name] = threading.Event()
            event = self._signal_events[signal_name]

        signaled = event.wait(timeout=timeout)
        if signaled:
            with self._lock:
                if signal_name in self._signals and self._signals[signal_name]:
                    return self._signals[signal_name][-1]
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

            signals_view = {}
            for sig_name, sigs in self._signals.items():
                signals_view[sig_name] = [{
                    "sender": s.sender,
                    "data": str(s.data) if s.data else None,
                } for s in sigs[-5:]]  # last 5

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

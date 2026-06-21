"""
Synsema Blackboard — Shared state for multi-agent coordination.

The blackboard is the "pheromone trail" of the agent swarm.
Every agent can:
    - share: publish data to a key
    - observe: read data from a key
    - watch: get notified when a key changes

The blackboard is:
    - Thread-safe (agents can run concurrently)
    - Observable (every read/write is logged)
    - Versioned (previous values are kept for debugging)
    - Typed (values are SynValues with full metadata)

This is NOT a simple dict. It's the coordination backbone.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from ..core.types import SynValue, syn_nothing


@dataclass
class BlackboardEntry:
    """A single entry in the blackboard with history."""
    key: str
    value: SynValue
    version: int = 1
    written_by: str = ""  # agent name
    written_at: float = 0.0
    history: List[tuple] = field(default_factory=list)  # (value, version, agent, time)


@dataclass
class BlackboardEvent:
    """An event emitted by the blackboard."""
    event_type: str  # "write", "read", "delete"
    key: str
    agent: str
    value: Optional[SynValue] = None
    timestamp: float = 0.0


class Blackboard:
    """
    Thread-safe shared state for agent coordination.

    The blackboard pattern: agents don't communicate directly.
    Instead, they read from and write to a shared space.
    This decouples agents and makes coordination emergent.
    """

    def __init__(self):
        self._data: Dict[str, BlackboardEntry] = {}
        self._lock = threading.RLock()
        self._watchers: Dict[str, List[Callable]] = {}  # key → callbacks
        self._events: List[BlackboardEvent] = []
        self._conditions: Dict[str, threading.Event] = {}

    def write(self, key: str, value: SynValue, agent: str = ""):
        """Write a value to the blackboard."""
        with self._lock:
            now = time.time()
            if key in self._data:
                entry = self._data[key]
                # Save history
                entry.history.append((
                    entry.value, entry.version, entry.written_by, entry.written_at
                ))
                entry.value = value
                entry.version += 1
                entry.written_by = agent
                entry.written_at = now
            else:
                self._data[key] = BlackboardEntry(
                    key=key, value=value,
                    written_by=agent, written_at=now,
                )

            # Log event
            self._events.append(BlackboardEvent(
                event_type="write", key=key, agent=agent,
                value=value, timestamp=now,
            ))

            # Notify watchers
            if key in self._watchers:
                for callback in self._watchers[key]:
                    try:
                        callback(key, value, agent)
                    except Exception:
                        pass

            # Signal any threads waiting on this key
            if key in self._conditions:
                self._conditions[key].set()

    def read(self, key: str, agent: str = "") -> Optional[SynValue]:
        """Read a value from the blackboard."""
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._events.append(BlackboardEvent(
                    event_type="read", key=key, agent=agent,
                    timestamp=time.time(),
                ))
                return None

            self._events.append(BlackboardEvent(
                event_type="read", key=key, agent=agent,
                value=entry.value, timestamp=time.time(),
            ))
            return entry.value

    def delete(self, key: str, agent: str = ""):
        """Delete a key from the blackboard."""
        with self._lock:
            if key in self._data:
                del self._data[key]
            self._events.append(BlackboardEvent(
                event_type="delete", key=key, agent=agent,
                timestamp=time.time(),
            ))

    def watch(self, key: str, callback: Callable):
        """Register a callback for when a key changes."""
        with self._lock:
            if key not in self._watchers:
                self._watchers[key] = []
            self._watchers[key].append(callback)

    def wait_for_key(self, key: str, timeout: float = None) -> Optional[SynValue]:
        """Block until a key is written, then return its value."""
        with self._lock:
            if key in self._data:
                return self._data[key].value
            if key not in self._conditions:
                self._conditions[key] = threading.Event()
            event = self._conditions[key]

        # Wait outside the lock
        signaled = event.wait(timeout=timeout)
        if signaled:
            return self.read(key)
        return None

    def keys(self) -> List[str]:
        """List all keys."""
        with self._lock:
            return list(self._data.keys())

    def snapshot(self) -> Dict[str, SynValue]:
        """Get a snapshot of all current values."""
        with self._lock:
            return {k: v.value for k, v in self._data.items()}

    def get_events(self, limit: int = 100) -> List[BlackboardEvent]:
        """Get recent events for debugging."""
        return self._events[-limit:]

    def get_entry_info(self, key: str) -> Optional[Dict]:
        """Get full info about a key (value, version, history)."""
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            return {
                "key": entry.key,
                "value": entry.value,
                "version": entry.version,
                "written_by": entry.written_by,
                "history_length": len(entry.history),
            }

"""
Synsema Resource Lock — Preventive conflict detection.

Instead of detecting conflicts AFTER they happen (like git merge conflicts),
the resource lock system prevents them BEFORE:

    - Agent A declares: "I'm working on file X"
    - Agent B tries to touch file X → BLOCKED (or queued)
    - Agent A finishes → Agent B can proceed

Resources can be:
    - Files: "/data/report.csv"
    - Functions: "task:process_order"
    - Blackboard keys: "bb:customer_data"
    - Database tables: "db:orders"
    - Any string identifier

Lock modes:
    - exclusive: only one agent at a time (write lock)
    - shared: multiple readers, no writers (read lock)
    - advisory: logged but not enforced (for observability)
"""

import threading
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum, auto


class LockMode(Enum):
    EXCLUSIVE = auto()   # One agent only (write)
    SHARED = auto()      # Multiple readers, no writers
    ADVISORY = auto()    # Logged, not enforced


class LockStatus(Enum):
    ACQUIRED = auto()
    WAITING = auto()
    DENIED = auto()
    RELEASED = auto()


@dataclass
class ResourceLock:
    """A lock on a specific resource."""
    resource: str
    agent: str
    mode: LockMode
    acquired_at: float = 0.0
    released_at: float = 0.0
    active: bool = True


@dataclass
class LockEvent:
    """Record of a lock operation."""
    event_type: str  # acquire, release, block, wait
    resource: str
    agent: str
    mode: LockMode
    timestamp: float = 0.0
    blocked_by: str = ""


class ResourceLockManager:
    """
    Manages resource locks for multi-agent coordination.

    This is the "before" mechanism that prevents conflicts.
    The blackboard handles "after" coordination (data sharing).
    Together they give the swarm safe, efficient coordination.
    """

    def __init__(self):
        self._locks: Dict[str, List[ResourceLock]] = {}  # resource → active locks
        self._lock = threading.RLock()
        self._wait_events: Dict[str, threading.Event] = {}
        self.events: List[LockEvent] = []

    def acquire(self, resource: str, agent: str,
                mode: LockMode = LockMode.EXCLUSIVE,
                timeout: float = None) -> LockStatus:
        """
        Try to acquire a lock on a resource.

        Returns ACQUIRED if successful, WAITING if blocking, DENIED if timeout.
        """
        with self._lock:
            existing = self._locks.get(resource, [])
            active_locks = [l for l in existing if l.active]

            # Check compatibility
            can_acquire = self._check_compatible(active_locks, agent, mode)

            if can_acquire:
                lock = ResourceLock(
                    resource=resource,
                    agent=agent,
                    mode=mode,
                    acquired_at=time.time(),
                )
                if resource not in self._locks:
                    self._locks[resource] = []
                self._locks[resource].append(lock)

                self.events.append(LockEvent(
                    event_type="acquire",
                    resource=resource,
                    agent=agent,
                    mode=mode,
                    timestamp=time.time(),
                ))
                return LockStatus.ACQUIRED

            # Cannot acquire — need to wait or deny
            blocked_by = ", ".join(l.agent for l in active_locks)
            self.events.append(LockEvent(
                event_type="block",
                resource=resource,
                agent=agent,
                mode=mode,
                timestamp=time.time(),
                blocked_by=blocked_by,
            ))

            if mode == LockMode.ADVISORY:
                # Advisory locks don't block
                lock = ResourceLock(
                    resource=resource, agent=agent,
                    mode=mode, acquired_at=time.time(),
                )
                self._locks[resource].append(lock)
                return LockStatus.ACQUIRED

        # Wait outside the lock
        if timeout is not None:
            wait_key = f"{resource}:{agent}"
            event = threading.Event()
            with self._lock:
                self._wait_events[wait_key] = event

            signaled = event.wait(timeout=timeout)

            with self._lock:
                self._wait_events.pop(wait_key, None)

            if signaled:
                # Try again
                return self.acquire(resource, agent, mode, timeout=0)

        return LockStatus.DENIED

    def release(self, resource: str, agent: str):
        """Release a lock on a resource."""
        with self._lock:
            if resource in self._locks:
                for lock in self._locks[resource]:
                    if lock.agent == agent and lock.active:
                        lock.active = False
                        lock.released_at = time.time()
                        self.events.append(LockEvent(
                            event_type="release",
                            resource=resource,
                            agent=agent,
                            mode=lock.mode,
                            timestamp=time.time(),
                        ))
                        break

                # Wake up anyone waiting for this resource
                for key, event in list(self._wait_events.items()):
                    if key.startswith(f"{resource}:"):
                        event.set()

    def release_all(self, agent: str):
        """Release all locks held by an agent."""
        with self._lock:
            for resource, locks in self._locks.items():
                for lock in locks:
                    if lock.agent == agent and lock.active:
                        lock.active = False
                        lock.released_at = time.time()

    def get_locks(self, resource: str = None) -> List[ResourceLock]:
        """Get active locks, optionally filtered by resource."""
        with self._lock:
            if resource:
                return [l for l in self._locks.get(resource, []) if l.active]
            all_locks = []
            for locks in self._locks.values():
                all_locks.extend(l for l in locks if l.active)
            return all_locks

    def get_agent_locks(self, agent: str) -> List[ResourceLock]:
        """Get all locks held by a specific agent."""
        with self._lock:
            result = []
            for locks in self._locks.values():
                result.extend(l for l in locks if l.active and l.agent == agent)
            return result

    def is_locked(self, resource: str) -> bool:
        """Check if a resource has any active locks."""
        with self._lock:
            return any(l.active for l in self._locks.get(resource, []))

    def who_holds(self, resource: str) -> List[str]:
        """Get which agents hold locks on a resource."""
        with self._lock:
            return [l.agent for l in self._locks.get(resource, []) if l.active]

    def _check_compatible(self, active_locks: List[ResourceLock],
                          agent: str, mode: LockMode) -> bool:
        """Check if a new lock is compatible with existing locks."""
        if not active_locks:
            return True

        # Same agent can re-acquire
        if all(l.agent == agent for l in active_locks):
            return True

        if mode == LockMode.EXCLUSIVE:
            # Exclusive needs no other locks
            return False

        if mode == LockMode.SHARED:
            # Shared is compatible with other shared, not exclusive
            return all(l.mode == LockMode.SHARED for l in active_locks)

        if mode == LockMode.ADVISORY:
            return True  # advisory always compatible

        return False

    def get_conflict_map(self) -> Dict[str, List[str]]:
        """
        Get a map of resources → agents for all active locks.

        This is the "hive mind view" of who is working on what.
        """
        with self._lock:
            result = {}
            for resource, locks in self._locks.items():
                agents = [l.agent for l in locks if l.active]
                if agents:
                    result[resource] = agents
            return result

    def format_status(self) -> str:
        """Format current lock status as readable text."""
        conflict_map = self.get_conflict_map()
        if not conflict_map:
            return "No active locks."
        lines = ["Resource Locks:"]
        for resource, agents in conflict_map.items():
            lines.append(f"  {resource}: {', '.join(agents)}")
        return "\n".join(lines)

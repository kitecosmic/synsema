"""
Syntecnia Capability Model.

Capabilities are the security foundation of Syntecnia. Instead of giving
a program full access and restricting afterward (like traditional OS permissions),
Syntecnia gives ZERO access by default and requires explicit capability grants.

A capability is a specific permission to perform a specific action on a specific scope:
    - net("api.example.com")     → HTTP access to that domain only
    - file("/data/reports/*")    → Read/write files matching that glob
    - file.read("/etc/config")   → Read-only access to that file
    - exec("ffmpeg")             → Permission to execute that binary
    - env("API_KEY")             → Access to that environment variable
    - time                       → Access to system clock
    - random                     → Access to random number generation
    - stdout                     → Permission to write to stdout

The capability system is hierarchical:
    - A parent scope grants access to children
    - net("*.example.com") covers net("api.example.com")
    - file("/data/*") covers file("/data/reports/q1.csv")

Capabilities are:
    - Declared: `require net("api.example.com")`
    - Checked: before every side-effecting operation
    - Scoped: each sandbox/agent gets its own capability set
    - Auditable: every check is logged
"""

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict
from enum import Enum, auto


class CapabilityType(Enum):
    """Categories of capabilities."""
    NET = auto()         # Network access
    FILE_READ = auto()   # File read
    FILE_WRITE = auto()  # File write
    FILE = auto()        # File read+write
    EXEC = auto()        # Execute external process
    ENV = auto()         # Environment variable access
    TIME = auto()        # System clock
    RANDOM = auto()      # Random number generation
    STDOUT = auto()      # Write to stdout
    STDIN = auto()       # Read from stdin
    LLM = auto()         # LLM API access
    DB = auto()           # Database access
    SERVE = auto()        # Bind/listen on a TCP port (HTTP server)


# Map from string names to types
CAPABILITY_NAMES = {
    "net": CapabilityType.NET,
    "file": CapabilityType.FILE,
    "file.read": CapabilityType.FILE_READ,
    "file.write": CapabilityType.FILE_WRITE,
    "exec": CapabilityType.EXEC,
    "env": CapabilityType.ENV,
    "time": CapabilityType.TIME,
    "random": CapabilityType.RANDOM,
    "stdout": CapabilityType.STDOUT,
    "stdin": CapabilityType.STDIN,
    "llm": CapabilityType.LLM,
    "db": CapabilityType.DB,
    "serve": CapabilityType.SERVE,
}


@dataclass(frozen=True)
class Capability:
    """
    A single capability grant.

    Examples:
        Capability(NET, "api.example.com")
        Capability(FILE, "/data/*")
        Capability(EXEC, "ffmpeg")
        Capability(TIME, None)  # no scope needed
    """
    type: CapabilityType
    scope: Optional[str] = None

    def covers(self, other: 'Capability') -> bool:
        """
        Does this capability grant cover the requested capability?

        Rules:
        - Same type required
        - FILE covers FILE_READ and FILE_WRITE
        - None scope (wildcard) covers everything of that type
        - Glob patterns: net("*.example.com") covers net("api.example.com")
        - Path patterns: file("/data/*") covers file("/data/report.csv")
        """
        # Type check
        if self.type != other.type:
            # FILE covers FILE_READ and FILE_WRITE
            if self.type == CapabilityType.FILE and other.type in (
                CapabilityType.FILE_READ, CapabilityType.FILE_WRITE
            ):
                pass  # allow
            else:
                return False

        # No scope = wildcard grant
        if self.scope is None:
            return True

        # Other has no scope = matches
        if other.scope is None:
            return self.scope is None

        # Exact match
        if self.scope == other.scope:
            return True

        # Glob/wildcard matching
        if fnmatch.fnmatch(other.scope, self.scope):
            return True

        return False

    def __str__(self):
        if self.scope:
            return f"{self.type.name.lower()}(\"{self.scope}\")"
        return self.type.name.lower()


@dataclass
class CapabilityAuditEntry:
    """Record of a capability check."""
    capability: Capability
    granted: bool
    source: str  # where in code the check happened
    reason: str  # why it was granted/denied


class CapabilitySet:
    """
    A set of granted capabilities with audit trail.

    This is assigned to each execution context (global, sandbox, agent).
    Every capability check is logged for full auditability.
    """

    def __init__(self, name: str = "default"):
        self.name = name
        self.granted: Set[Capability] = set()
        self.denied: Set[Capability] = set()  # explicit denials override grants
        self.audit_log: List[CapabilityAuditEntry] = []
        self.parent: Optional['CapabilitySet'] = None

    def grant(self, capability: Capability):
        """Grant a capability."""
        self.granted.add(capability)

    def deny(self, capability: Capability):
        """Explicitly deny a capability (overrides grants)."""
        self.denied.add(capability)

    def check(self, requested: Capability, source: str = "") -> bool:
        """
        Check if a capability is allowed.

        Returns True if granted and not denied.
        Every check is logged to the audit trail.
        """
        # Check explicit denials first
        for denied in self.denied:
            if denied.covers(requested):
                entry = CapabilityAuditEntry(
                    capability=requested,
                    granted=False,
                    source=source,
                    reason=f"Explicitly denied by {denied}",
                )
                self.audit_log.append(entry)
                return False

        # Check grants
        for cap in self.granted:
            if cap.covers(requested):
                entry = CapabilityAuditEntry(
                    capability=requested,
                    granted=True,
                    source=source,
                    reason=f"Granted by {cap}",
                )
                self.audit_log.append(entry)
                return True

        # Check parent
        if self.parent and self.parent.check(requested, source):
            return True

        # Not granted
        entry = CapabilityAuditEntry(
            capability=requested,
            granted=False,
            source=source,
            reason="No matching grant found",
        )
        self.audit_log.append(entry)
        return False

    def require(self, requested: Capability, source: str = ""):
        """Check capability and raise if not granted."""
        if not self.check(requested, source):
            raise CapabilityViolation(
                f"Capability not granted: {requested}",
                requested=requested,
                source=source,
            )

    def create_child(self, name: str) -> 'CapabilitySet':
        """Create a child capability set (for sandboxes, agents)."""
        child = CapabilitySet(name=name)
        child.parent = self
        return child

    def create_sandbox(self, name: str, allowed: List[Capability] = None) -> 'CapabilitySet':
        """
        Create a restricted sandbox capability set.

        Unlike create_child, a sandbox does NOT inherit from parent.
        It only has the capabilities explicitly granted to it.
        """
        sandbox = CapabilitySet(name=f"sandbox:{name}")
        # No parent — complete isolation
        if allowed:
            for cap in allowed:
                sandbox.grant(cap)
        return sandbox

    def get_audit_report(self) -> str:
        """Generate a human-readable audit report."""
        lines = [f"Capability Audit Report: {self.name}"]
        lines.append(f"  Grants: {len(self.granted)}")
        lines.append(f"  Denials: {len(self.denied)}")
        lines.append(f"  Checks: {len(self.audit_log)}")
        lines.append("")

        for entry in self.audit_log:
            status = "GRANTED" if entry.granted else "DENIED"
            lines.append(f"  [{status}] {entry.capability} at {entry.source}")
            lines.append(f"    Reason: {entry.reason}")

        return "\n".join(lines)


class CapabilityViolation(Exception):
    """Raised when code tries to use a capability it doesn't have."""
    def __init__(self, message: str, requested: Capability = None, source: str = ""):
        self.requested = requested
        self.source = source
        super().__init__(message)


def parse_capability(name: str, scope: Optional[str] = None) -> Capability:
    """Parse a capability from its name and optional scope string."""
    cap_type = CAPABILITY_NAMES.get(name)
    if cap_type is None:
        raise ValueError(f"Unknown capability type: '{name}'. Known: {list(CAPABILITY_NAMES.keys())}")
    return Capability(type=cap_type, scope=scope)

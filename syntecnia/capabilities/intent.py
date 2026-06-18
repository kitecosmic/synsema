"""
Syntecnia Intent Declaration.

The `intent:` declaration states, in plain language, WHAT the program is for.
It is a human-readable description, used for:
    - Auditing (shown in the intent report / --audit)
    - LLM context (every reasoning call sees the program's purpose)
    - Documentation

IMPORTANT — the intent is DESCRIPTIVE, not a security mechanism.

Security is enforced *exclusively* by capabilities (`require net(...)`,
`require file(...)`, ...), which are explicit, scoped, and fail with a clear,
actionable error when an undeclared action is attempted. The intent does NOT
block actions.

This is a deliberate design choice: the language has exactly ONE explicit
authorization model (capabilities). The old behavior — guessing allowed
action categories by scanning the intent prose for keywords, and silently
falling back to permissive when no keyword matched — was unpredictable and
language/word dependent, so it was removed. A serious language must be
predictable: you declare what you need with `require`, and using anything
undeclared is a clear error.

Anti-prompt-injection: the intent FREEZES once execution starts, so malicious
input cannot redeclare a broader intent. The freeze is enforced in the
interpreter (re-declaring a frozen intent raises an error).
"""

from dataclasses import dataclass
from typing import List, Optional, Dict
from enum import Enum, auto


class ActionCategory(Enum):
    """
    Labels for side-effecting operations, used only for the audit log.
    Informational — they do NOT gate execution (capabilities do that).
    """
    DATA_READ = auto()
    DATA_WRITE = auto()
    NET_READ = auto()
    NET_WRITE = auto()
    FILE_READ = auto()
    FILE_WRITE = auto()
    EXEC = auto()
    COMMUNICATE = auto()
    COMPUTE = auto()
    HUMAN_INTERACT = auto()
    LLM_REASON = auto()
    AGENT_SPAWN = auto()
    AGENT_SIGNAL = auto()


@dataclass
class IntentScope:
    """A declared intent: a human-readable description of the program's purpose."""
    description: str
    frozen: bool = False  # once frozen, cannot be redeclared (anti-injection)


@dataclass
class IntentViolation:
    """
    Kept for backward compatibility. The intent no longer blocks actions, so
    violations are never produced here. Security violations are reported by the
    capability layer (CapabilityViolation), not by the intent.
    """
    action: str = ""
    detail: str = ""
    intent_description: str = ""


class IntentEnforcer:
    """
    Holds the program's declared intent (a description).

    The intent is descriptive: it provides audit context and LLM context.
    It does NOT authorize or block actions — capabilities do that.
    `check_action` records the action for the audit log and always allows it.
    """

    def __init__(self):
        self.intent: Optional[IntentScope] = None
        self.checks: List[Dict] = []
        # Always empty: the intent never blocks. Kept for backward compatibility.
        self.violations: List[IntentViolation] = []
        self.strict: bool = True  # retained for API compatibility; has no effect

    def set_intent(self, description: str):
        """Set the program's intent description."""
        self.intent = IntentScope(description=description)

    def freeze_intent(self):
        """Freeze the intent so it cannot be redeclared after execution starts."""
        if self.intent:
            self.intent.frozen = True

    def check_action(self, category: ActionCategory, detail: str = "",
                     domain: str = None, path: str = None) -> bool:
        """
        Record an action for the audit log and ALWAYS allow it.

        The intent is descriptive only; security is enforced by capabilities,
        not here. Returns True unconditionally.
        """
        self.checks.append({
            "category": category.name if category else "?",
            "detail": detail,
            "result": "allowed",
            "reason": "intent_is_descriptive",
        })
        return True

    def get_report(self) -> str:
        """Human-readable intent report (description only; not a security gate)."""
        lines = ["Intent Report"]
        if self.intent:
            lines.append(f"  Intent: {self.intent.description}")
            lines.append(f"  Frozen: {self.intent.frozen}")
            lines.append("  Security: enforced by capabilities (require), not by the intent text.")
        else:
            lines.append("  No intent declared.")
        lines.append(f"\n  Actions recorded: {len(self.checks)}")
        return "\n".join(lines)

"""
Syntecnia Agent Memory — Persistent knowledge system.

An agent's memory stores everything it learns and everything its
owner configures. This is NOT the blackboard (which is runtime shared state).
This is persistent knowledge that survives across executions.

Memory categories:
    - preferences: Owner's preferences ("formal tone", "metric units")
    - rules: Business rules and directives ("never discount > 20%")
    - learnings: Things the agent discovered ("API X is slow on Mondays")
    - decisions: Past decisions and their outcomes
    - context: Background info about the domain

Rules have enforcement levels:
    - must: Hard rule, violation is an error
    - should: Soft rule, violation triggers a warning
    - avoid: Preference to avoid, but not blocked
    - prefer: Preference to do, but not required

Everything is stored as structured JSON so agents can query
programmatically, not just read text.
"""

import json
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class RuleLevel(Enum):
    MUST = "must"           # Hard rule — violation is error
    SHOULD = "should"       # Soft rule — violation is warning
    AVOID = "avoid"         # Preference against
    PREFER = "prefer"       # Preference for


class MemoryCategory(Enum):
    PREFERENCE = "preference"
    RULE = "rule"
    LEARNING = "learning"
    DECISION = "decision"
    CONTEXT = "context"


@dataclass
class MemoryEntry:
    """A single entry in the agent's memory."""
    id: str
    category: MemoryCategory
    content: str                    # Human-readable description
    data: Dict[str, Any] = field(default_factory=dict)  # Structured data
    tags: List[str] = field(default_factory=list)        # For search
    created_at: float = 0.0
    updated_at: float = 0.0
    source: str = ""               # Who created this (owner, agent, system)
    confidence: float = 1.0        # 0-1, how sure we are
    active: bool = True            # Can be deactivated without deleting

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "content": self.content,
            "data": self.data,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "source": self.source,
            "confidence": self.confidence,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> 'MemoryEntry':
        return cls(
            id=d["id"],
            category=MemoryCategory(d["category"]),
            content=d["content"],
            data=d.get("data", {}),
            tags=d.get("tags", []),
            created_at=d.get("created_at", 0),
            updated_at=d.get("updated_at", 0),
            source=d.get("source", ""),
            confidence=d.get("confidence", 1.0),
            active=d.get("active", True),
        )


@dataclass
class OwnerRule:
    """
    A directive from the agent's owner.

    Examples:
        OwnerRule(
            name="max_discount",
            level=MUST,
            description="Never offer discounts greater than 20%",
            condition="discount <= 0.20",
            action="block",
        )
        OwnerRule(
            name="formal_tone",
            level=PREFER,
            description="Use formal tone in customer communications",
            action="warn",
        )
    """
    name: str
    level: RuleLevel
    description: str
    condition: Optional[str] = None    # Evaluable condition
    action: str = "warn"               # "block", "warn", "log"
    category: str = ""                 # "pricing", "communication", "security"
    tags: List[str] = field(default_factory=list)
    active: bool = True

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "level": self.level.value,
            "description": self.description,
            "condition": self.condition,
            "action": self.action,
            "category": self.category,
            "tags": self.tags,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> 'OwnerRule':
        return cls(
            name=d["name"],
            level=RuleLevel(d["level"]),
            description=d["description"],
            condition=d.get("condition"),
            action=d.get("action", "warn"),
            category=d.get("category", ""),
            tags=d.get("tags", []),
            active=d.get("active", True),
        )


class RuleViolation:
    """Raised or logged when a rule is violated."""
    def __init__(self, rule: OwnerRule, detail: str = ""):
        self.rule = rule
        self.detail = detail
        self.timestamp = time.time()

    def __str__(self):
        return (
            f"[{self.rule.level.value.upper()}] Rule '{self.rule.name}' violated: "
            f"{self.rule.description}. {self.detail}"
        )


class AgentMemory:
    """
    Persistent memory system for an agent.

    Stores preferences, rules, learnings, decisions, and context.
    Everything persists to a JSON file.

    Usage in Syntecnia:
        remember "preference" "Customer prefers email over phone" tagged ["communication"]
        recall tagged "pricing"
        check_rules "discount" value 0.25  -- would warn about max_discount rule
    """

    def __init__(self, persist_path: str = None):
        self.entries: Dict[str, MemoryEntry] = {}
        self.rules: Dict[str, OwnerRule] = {}
        self.violations: List[RuleViolation] = []
        self.persist_path = persist_path
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"mem_{self._counter}"

    # -- Memory operations --

    def remember(self, category: str, content: str,
                 data: Dict = None, tags: List[str] = None,
                 source: str = "agent") -> MemoryEntry:
        """Store something in memory."""
        valid_categories = [c.value for c in MemoryCategory]
        try:
            cat = MemoryCategory(category)
        except ValueError:
            raise ValueError(
                f"Invalid memory category: '{category}'. "
                f"Valid categories: {', '.join(valid_categories)}"
            )
        entry = MemoryEntry(
            id=self._next_id(),
            category=cat,
            content=content,
            data=data or {},
            tags=tags or [],
            source=source,
        )
        self.entries[entry.id] = entry
        self._persist()
        return entry

    def recall(self, category: str = None, tags: List[str] = None,
               search: str = None, limit: int = 20) -> List[MemoryEntry]:
        """Search memory by category, tags, or text search."""
        results = []
        for entry in self.entries.values():
            if not entry.active:
                continue
            if category and entry.category.value != category:
                continue
            if tags and not any(t in entry.tags for t in tags):
                continue
            if search and search.lower() not in entry.content.lower():
                match_in_data = any(
                    search.lower() in str(v).lower()
                    for v in entry.data.values()
                )
                if not match_in_data:
                    continue
            results.append(entry)

        # Sort by recency
        results.sort(key=lambda e: e.updated_at, reverse=True)
        return results[:limit]

    def forget(self, entry_id: str):
        """Deactivate a memory entry (soft delete)."""
        if entry_id in self.entries:
            self.entries[entry_id].active = False
            self._persist()

    def update(self, entry_id: str, content: str = None,
               data: Dict = None, confidence: float = None):
        """Update an existing memory entry."""
        entry = self.entries.get(entry_id)
        if not entry:
            return
        if content is not None:
            entry.content = content
        if data is not None:
            entry.data.update(data)
        if confidence is not None:
            entry.confidence = confidence
        entry.updated_at = time.time()
        self._persist()

    # -- Rule operations --

    def add_rule(self, name: str, level: str, description: str,
                 condition: str = None, action: str = "warn",
                 category: str = "", tags: List[str] = None) -> OwnerRule:
        """Add an owner rule."""
        # Auto-extract condition from description if not provided
        if condition is None:
            import re
            cond_match = re.search(r'(\w+\s*(?:<=|>=|<|>|==|!=)\s*[\d.]+)', description)
            if cond_match:
                condition = cond_match.group(1)
        rule = OwnerRule(
            name=name,
            level=RuleLevel(level),
            description=description,
            condition=condition,
            action=action,
            category=category,
            tags=tags or [],
        )
        self.rules[name] = rule
        self._persist()
        return rule

    def check_rules(self, category: str = None,
                    tags: List[str] = None,
                    context: Dict[str, Any] = None) -> List[RuleViolation]:
        """
        Check applicable rules against current context.

        Returns list of violations (empty = all rules pass).
        Context is a dict of named values that rules can reference.
        """
        violations = []
        for rule in self.rules.values():
            if not rule.active:
                continue
            if category and rule.category and rule.category != category:
                continue
            if tags and not any(t in rule.tags for t in tags):
                continue

            # Check condition if present and context provided
            if rule.condition and context:
                violated = self._evaluate_condition(rule.condition, context)
                if violated:
                    v = RuleViolation(rule, f"Context: {context}")
                    violations.append(v)
                    self.violations.append(v)

        return violations

    def _evaluate_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate a rule condition against context.
        Returns True if the rule is VIOLATED.

        Condition format: "variable operator value"
        Example: "discount <= 0.20" means the rule is that discount must be <= 0.20
                 If discount > 0.20, the rule is violated → return True
        """
        import re
        # Parse: "name op value"
        match = re.match(r'(\w+)\s*(<=|>=|<|>|==|!=)\s*(.+)', condition.strip())
        if not match:
            return False

        var_name = match.group(1)
        operator = match.group(2)
        threshold_str = match.group(3).strip()

        if var_name not in context:
            return False

        try:
            actual = float(context[var_name])
            threshold = float(threshold_str)
        except (ValueError, TypeError):
            return False

        # The condition describes what SHOULD be true.
        # Violation = condition is false.
        if operator == "<=":
            return not (actual <= threshold)
        elif operator == ">=":
            return not (actual >= threshold)
        elif operator == "<":
            return not (actual < threshold)
        elif operator == ">":
            return not (actual > threshold)
        elif operator == "==":
            return not (actual == threshold)
        elif operator == "!=":
            return not (actual != threshold)

        return False

    def get_rules(self, category: str = None,
                  level: str = None) -> List[OwnerRule]:
        """Get rules, optionally filtered."""
        results = []
        for rule in self.rules.values():
            if not rule.active:
                continue
            if category and rule.category != category:
                continue
            if level and rule.level.value != level:
                continue
            results.append(rule)
        return results

    def remove_rule(self, name: str):
        """Deactivate a rule."""
        if name in self.rules:
            self.rules[name].active = False
            self._persist()

    # -- Persistence --

    def _persist(self):
        if not self.persist_path:
            return
        data = {
            "entries": {k: v.to_dict() for k, v in self.entries.items()},
            "rules": {k: v.to_dict() for k, v in self.rules.items()},
        }
        Path(self.persist_path).write_text(json.dumps(data, indent=2))

    def load(self):
        """Load persisted memory."""
        if not self.persist_path:
            return
        path = Path(self.persist_path)
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for k, v in data.get("entries", {}).items():
            self.entries[k] = MemoryEntry.from_dict(v)
            self._counter = max(self._counter, int(k.split("_")[1]) if "_" in k else 0)
        for k, v in data.get("rules", {}).items():
            self.rules[k] = OwnerRule.from_dict(v)

    # -- Display --

    def format_summary(self) -> str:
        """Human-readable memory summary."""
        active_entries = [e for e in self.entries.values() if e.active]
        active_rules = [r for r in self.rules.values() if r.active]

        lines = [f"Agent Memory: {len(active_entries)} entries, {len(active_rules)} rules"]

        by_cat = {}
        for e in active_entries:
            cat = e.category.value
            by_cat[cat] = by_cat.get(cat, 0) + 1
        if by_cat:
            lines.append("  Entries: " + ", ".join(f"{v} {k}" for k, v in by_cat.items()))

        if active_rules:
            lines.append("  Rules:")
            for r in active_rules:
                lines.append(f"    [{r.level.value:6s}] {r.name}: {r.description}")

        if self.violations:
            lines.append(f"  Recent violations: {len(self.violations)}")
            for v in self.violations[-5:]:
                lines.append(f"    {v}")

        return "\n".join(lines)

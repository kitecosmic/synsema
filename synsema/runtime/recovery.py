"""
Synsema Recovery Protocol — Automatic error recovery and human escalation.

When an error occurs, the recovery protocol:

    1. DIAGNOSE — Build rich error diagnostic
    2. RECOVER — Try automatic recovery strategies
    3. ESCALATE — If recovery fails, present structured options to human
    4. RECORD — Log the decision for future reference

Recovery strategies (tried in order):
    - retry: Try the same operation again (for transient IO errors)
    - fallback: Use cached/default data
    - partial: Continue with partial results
    - speculate: Try alternative approaches via speculative execution

Escalation presents:
    - What happened
    - What was tried
    - Options with impact analysis
    - Waits for human decision

Decision recording:
    - Every human decision is stored with context
    - Future runs can consult past decisions
    - Enables "precedent-based" recovery
"""

import time
import json
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from pathlib import Path
from .error_reporter import ErrorDiagnostic, ErrorReporter
from ..core.types import SynValue, syn_nothing, syn_text, syn_bool


@dataclass
class RecoveryAttempt:
    """Record of a single recovery attempt."""
    strategy: str        # "retry", "fallback", "partial", "speculate"
    description: str     # What was tried
    success: bool = False
    result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float = 0


@dataclass
class EscalationOption:
    """An option presented to the human during escalation."""
    key: str             # "A", "B", "C", etc.
    label: str           # Short description
    description: str     # Detailed explanation
    impact: str          # What happens if this is chosen
    requires: List[str] = field(default_factory=list)  # capabilities needed
    auto_action: Optional[Callable] = None  # automated follow-up


@dataclass
class HumanDecision:
    """A recorded human decision."""
    timestamp: float
    error_type: str
    error_message: str
    context: str          # what the program was doing
    options_presented: List[str]
    chosen_option: str
    chosen_label: str
    outcome: str = ""     # filled in after the decision plays out
    agent_name: str = ""


@dataclass
class RecoveryResult:
    """Final result of the recovery process."""
    recovered: bool = False
    value: Optional[SynValue] = None
    strategy_used: str = ""
    attempts: List[RecoveryAttempt] = field(default_factory=list)
    escalated: bool = False
    human_decision: Optional[HumanDecision] = None
    diagnostic: Optional[ErrorDiagnostic] = None


class RecoveryProtocol:
    """
    Orchestrates error recovery and human escalation.

    Usage:
        protocol = RecoveryProtocol(error_reporter, human_callback)

        try:
            result = risky_operation()
        except Exception as e:
            recovery = protocol.handle_error(e, env, strategies=[...])
            if recovery.recovered:
                result = recovery.value
            else:
                # completely unrecoverable
                raise
    """

    def __init__(self, error_reporter: ErrorReporter = None,
                 human_callback: Callable = None,
                 output_callback: Callable = None):
        self.error_reporter = error_reporter or ErrorReporter()
        self.human_callback = human_callback
        self.output_callback = output_callback
        self.decision_log: List[HumanDecision] = []
        self.max_retry_attempts = 3
        self.retry_backoff_ms = [100, 500, 2000]  # exponential-ish

    def _output(self, text: str):
        if self.output_callback:
            self.output_callback(text)

    def handle_error(self, error: Exception, env=None,
                     retry_fn: Callable = None,
                     fallback_value: SynValue = None,
                     partial_fn: Callable = None,
                     speculate_fns: List[Callable] = None,
                     escalation_options: List[EscalationOption] = None,
                     context: str = "") -> RecoveryResult:
        """
        Full recovery protocol for an error.

        Steps:
        1. Diagnose the error
        2. Try automatic recovery strategies
        3. If all fail, escalate to human
        4. Record the decision
        """
        result = RecoveryResult()

        # Step 1: Diagnose
        diag = self.error_reporter.build_diagnostic(error, env)
        result.diagnostic = diag

        self._output(f"[RECOVERY] Error detected: {diag.message}")
        self._output(f"[RECOVERY] Category: {diag.error_category}, Recoverable: {diag.recoverable}")

        # Step 2: Try automatic strategies
        # If caller provides recovery strategies, try them regardless of classification.
        # The recoverable flag is a hint, not a gate — the caller knows best.
        has_strategies = any([retry_fn, fallback_value is not None, partial_fn, speculate_fns])
        if diag.recoverable or has_strategies:
            # Strategy: Retry (for IO/transient errors or caller-provided retry)
            if retry_fn and (diag.retry_makes_sense or has_strategies):
                attempt = self._try_retry(retry_fn)
                result.attempts.append(attempt)
                if attempt.success:
                    result.recovered = True
                    result.value = attempt.result
                    result.strategy_used = "retry"
                    self._output(f"[RECOVERY] Recovered via retry")
                    return result

            # Strategy: Fallback value
            if fallback_value is not None:
                attempt = RecoveryAttempt(
                    strategy="fallback",
                    description="Using fallback value",
                    success=True,
                    result=fallback_value,
                )
                result.attempts.append(attempt)
                result.recovered = True
                result.value = fallback_value
                result.strategy_used = "fallback"
                self._output(f"[RECOVERY] Recovered via fallback value")
                return result

            # Strategy: Partial results
            if partial_fn:
                attempt = self._try_partial(partial_fn)
                result.attempts.append(attempt)
                if attempt.success:
                    result.recovered = True
                    result.value = attempt.result
                    result.strategy_used = "partial"
                    self._output(f"[RECOVERY] Recovered via partial results")
                    return result

            # Strategy: Speculative alternatives
            if speculate_fns:
                for i, spec_fn in enumerate(speculate_fns):
                    attempt = self._try_speculate(spec_fn, i)
                    result.attempts.append(attempt)
                    if attempt.success:
                        result.recovered = True
                        result.value = attempt.result
                        result.strategy_used = f"speculate:{i}"
                        self._output(f"[RECOVERY] Recovered via alternative approach {i}")
                        return result

        # Step 3: All automatic strategies failed — escalate to human
        self._output(f"[RECOVERY] Automatic recovery failed. Escalating to human.")
        result.escalated = True

        if self.human_callback:
            decision = self._escalate_to_human(diag, result.attempts,
                                                escalation_options, context)
            result.human_decision = decision

            if decision:
                self.decision_log.append(decision)

                # Execute the chosen option's auto_action if it has one
                if escalation_options:
                    for opt in escalation_options:
                        if opt.key == decision.chosen_option and opt.auto_action:
                            try:
                                action_result = opt.auto_action()
                                result.recovered = True
                                result.value = action_result if isinstance(action_result, SynValue) else syn_text(str(action_result))
                                result.strategy_used = f"human:{decision.chosen_option}"
                            except Exception as e:
                                result.recovered = False
                            break
        else:
            self._output(f"[RECOVERY] No human handler configured. Error is unrecoverable.")

        return result

    def _try_retry(self, retry_fn: Callable) -> RecoveryAttempt:
        """Try retrying the operation with backoff."""
        for i in range(self.max_retry_attempts):
            attempt_num = i + 1
            backoff = self.retry_backoff_ms[min(i, len(self.retry_backoff_ms) - 1)]
            self._output(f"[RECOVERY] Retry attempt {attempt_num}/{self.max_retry_attempts} (backoff: {backoff}ms)")

            if backoff > 0:
                time.sleep(backoff / 1000)

            try:
                result = retry_fn()
                return RecoveryAttempt(
                    strategy="retry",
                    description=f"Retry attempt {attempt_num} succeeded",
                    success=True,
                    result=result,
                )
            except Exception as e:
                if attempt_num == self.max_retry_attempts:
                    return RecoveryAttempt(
                        strategy="retry",
                        description=f"All {self.max_retry_attempts} retry attempts failed",
                        success=False,
                        error=str(e),
                    )

        return RecoveryAttempt(strategy="retry", description="Retry exhausted", success=False)

    def _try_partial(self, partial_fn: Callable) -> RecoveryAttempt:
        """Try getting partial results."""
        self._output(f"[RECOVERY] Trying partial results strategy")
        try:
            result = partial_fn()
            return RecoveryAttempt(
                strategy="partial",
                description="Partial results obtained",
                success=True,
                result=result,
            )
        except Exception as e:
            return RecoveryAttempt(
                strategy="partial",
                description="Partial results failed",
                success=False,
                error=str(e),
            )

    def _try_speculate(self, spec_fn: Callable, index: int) -> RecoveryAttempt:
        """Try an alternative approach."""
        self._output(f"[RECOVERY] Trying alternative approach {index}")
        try:
            result = spec_fn()
            return RecoveryAttempt(
                strategy=f"speculate:{index}",
                description=f"Alternative approach {index} succeeded",
                success=True,
                result=result,
            )
        except Exception as e:
            return RecoveryAttempt(
                strategy=f"speculate:{index}",
                description=f"Alternative approach {index} failed",
                success=False,
                error=str(e),
            )

    def _escalate_to_human(self, diag: ErrorDiagnostic,
                           attempts: List[RecoveryAttempt],
                           options: List[EscalationOption] = None,
                           context: str = "") -> Optional[HumanDecision]:
        """Present a structured escalation to the human."""
        # Build the escalation message
        lines = []
        lines.append("ESCALATION REQUIRED")
        lines.append("")
        lines.append(f"  Situation: {diag.message}")
        if context:
            lines.append(f"  Context: {context}")
        if diag.active_intent:
            lines.append(f"  Intent: {diag.active_intent}")

        if attempts:
            lines.append("")
            lines.append("  What was tried:")
            for i, attempt in enumerate(attempts, 1):
                status = "OK" if attempt.success else "FAILED"
                lines.append(f"    {i}. [{status}] {attempt.description}")
                if attempt.error:
                    lines.append(f"       Error: {attempt.error}")

        # Build default options if none provided
        if not options:
            options = self._generate_default_options(diag)

        lines.append("")
        lines.append("  Options:")
        for opt in options:
            lines.append(f"    {opt.key}) {opt.label}")
            lines.append(f"       {opt.description}")
            lines.append(f"       Impact: {opt.impact}")

        escalation_text = "\n".join(lines)
        self._output(escalation_text)

        # Ask the human
        option_keys = [opt.key for opt in options]
        option_labels = {opt.key: opt.label for opt in options}
        prompt = f"Choose option ({', '.join(option_keys)})"

        response = self.human_callback("ask", prompt)
        chosen = str(response).strip().upper()

        # Normalize response
        if chosen not in option_labels:
            # Try matching by first letter or number
            for opt in options:
                if chosen == opt.key or chosen == opt.label[:len(chosen)].upper():
                    chosen = opt.key
                    break

        chosen_label = option_labels.get(chosen, chosen)

        decision = HumanDecision(
            timestamp=time.time(),
            error_type=diag.error_type,
            error_message=diag.message,
            context=context or diag.active_intent or "",
            options_presented=[f"{o.key}: {o.label}" for o in options],
            chosen_option=chosen,
            chosen_label=chosen_label,
        )

        self._output(f"[DECISION] Human chose: {chosen} — {chosen_label}")
        return decision

    def _generate_default_options(self, diag: ErrorDiagnostic) -> List[EscalationOption]:
        """Generate default escalation options based on error type."""
        options = []

        if diag.retry_makes_sense:
            options.append(EscalationOption(
                key="A",
                label="Retry later",
                description="Pause and retry after a delay",
                impact="Operation will be delayed but may succeed",
            ))

        if diag.error_category == "io":
            options.append(EscalationOption(
                key="B",
                label="Use fallback",
                description="Continue with default/cached data",
                impact="Results may be incomplete or outdated",
            ))

        if diag.error_category == "data":
            options.append(EscalationOption(
                key="C",
                label="Skip this item",
                description="Skip the problematic data and continue",
                impact="Some items will be missing from results",
            ))

        options.append(EscalationOption(
            key="D",
            label="Abort",
            description="Stop the entire operation",
            impact="Nothing will be processed",
        ))

        # Ensure at least A, B labels if we didn't add IO/data specific ones
        if len(options) == 1:
            options.insert(0, EscalationOption(
                key="A",
                label="Retry once",
                description="Try the operation one more time",
                impact="May succeed if the issue was transient",
            ))

        # Re-key options sequentially
        for i, opt in enumerate(options):
            opt.key = chr(65 + i)  # A, B, C, D...

        return options

    # -- Decision persistence --

    def save_decisions(self, filepath: str):
        """Save decision log to a JSON file."""
        data = []
        for d in self.decision_log:
            data.append({
                "timestamp": d.timestamp,
                "error_type": d.error_type,
                "error_message": d.error_message,
                "context": d.context,
                "options": d.options_presented,
                "chosen": d.chosen_option,
                "chosen_label": d.chosen_label,
                "outcome": d.outcome,
            })
        Path(filepath).write_text(json.dumps(data, indent=2))

    def load_decisions(self, filepath: str):
        """Load past decisions for precedent-based recovery."""
        path = Path(filepath)
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for d in data:
            self.decision_log.append(HumanDecision(
                timestamp=d["timestamp"],
                error_type=d["error_type"],
                error_message=d["error_message"],
                context=d.get("context", ""),
                options_presented=d.get("options", []),
                chosen_option=d["chosen"],
                chosen_label=d.get("chosen_label", ""),
                outcome=d.get("outcome", ""),
            ))

    def find_precedent(self, error_type: str, context: str = "") -> Optional[HumanDecision]:
        """
        Find a past decision for a similar error.

        This enables "the human decided X last time this happened"
        behavior — the agent can auto-apply past decisions.
        """
        for decision in reversed(self.decision_log):
            if decision.error_type == error_type:
                if not context or context in decision.context:
                    return decision
        return None

    def get_decision_summary(self) -> str:
        """Format decision history."""
        if not self.decision_log:
            return "No decisions recorded."
        lines = [f"Decision History ({len(self.decision_log)} decisions):"]
        for d in self.decision_log:
            lines.append(f"  [{d.error_type}] {d.error_message[:50]}...")
            lines.append(f"    Chose: {d.chosen_option} — {d.chosen_label}")
            if d.outcome:
                lines.append(f"    Outcome: {d.outcome}")
        return "\n".join(lines)

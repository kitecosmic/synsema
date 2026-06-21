"""
Synsema LLM Response Validator.

Every LLM response must match what the language expects.
If it doesn't, we retry with feedback explaining what was wrong.

Validation rules by operation:

    decide → response must be EXACTLY one of the given options
    analyze → response must be non-empty text
    generate → response must be non-empty text
    reason → response must be non-empty text

For decide, this is critical: if the LLM says "I think option A is best
because..." instead of just "A", the program breaks. The validator
catches this and retries with: "Your response 'I think option A...'
is invalid. Respond with ONLY one of: refund, replace, escalate"

Retry strategy:
    - Attempt 1: original prompt
    - Attempt 2: original prompt + "Your previous response was invalid: {reason}"
    - Attempt 3: simplified prompt + stronger instruction
    - After 3 failures: return error or fallback
"""

import re
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    """Result of validating an LLM response."""
    valid: bool
    value: str = ""           # The cleaned/extracted value
    raw_response: str = ""    # What the LLM actually said
    error: str = ""           # Why it was invalid
    attempts: int = 0


@dataclass
class ValidationRule:
    """A rule for validating a specific operation's response."""
    operation: str
    check: Callable[[str, Dict], 'ValidationResult']


def validate_decide(response: str, data: Dict) -> ValidationResult:
    """
    Validate a 'decide' response — must be exactly one of the options.

    Handles common LLM mistakes:
    - Extra text: "I would choose refund" → extracts "refund"
    - Numbering: "1" or "Option 1" → maps to first option
    - Quotes: '"refund"' → strips to 'refund'
    - Case mismatch: "Refund" → matches "refund"
    """
    options_str = str(data.get("options", ""))
    # Parse options from string representation
    options = _parse_options(options_str)

    if not options:
        # No options to validate against
        return ValidationResult(valid=True, value=response.strip(), raw_response=response)

    cleaned = response.strip().strip('"').strip("'").strip()

    # Exact match (case-insensitive)
    for opt in options:
        if cleaned.lower() == opt.lower():
            return ValidationResult(valid=True, value=opt, raw_response=response)

    # Number match: "1" → first option
    if cleaned.isdigit():
        idx = int(cleaned) - 1
        if 0 <= idx < len(options):
            return ValidationResult(valid=True, value=options[idx], raw_response=response)

    # "Option X" or "Choice X"
    num_match = re.search(r'(?:option|choice)\s*(\d+)', cleaned, re.IGNORECASE)
    if num_match:
        idx = int(num_match.group(1)) - 1
        if 0 <= idx < len(options):
            return ValidationResult(valid=True, value=options[idx], raw_response=response)

    # Check if any option appears in the response
    found = []
    for opt in options:
        if opt.lower() in cleaned.lower():
            found.append(opt)

    if len(found) == 1:
        return ValidationResult(valid=True, value=found[0], raw_response=response)

    # Nothing matched
    return ValidationResult(
        valid=False,
        raw_response=response,
        error=f"Response '{cleaned}' is not one of the valid options: {options}",
    )


def validate_text_response(response: str, data: Dict) -> ValidationResult:
    """Validate analyze/generate/reason — must be non-empty text."""
    cleaned = response.strip()
    if not cleaned:
        return ValidationResult(
            valid=False,
            raw_response=response,
            error="Response is empty",
        )
    # Check for common error patterns
    if cleaned.startswith("[") and "error" in cleaned.lower():
        return ValidationResult(
            valid=False,
            raw_response=response,
            error=f"LLM returned an error: {cleaned}",
        )
    return ValidationResult(valid=True, value=cleaned, raw_response=response)


def _parse_options(options_str: str) -> List[str]:
    """Parse options from various string formats."""
    # Handle list format: ["a", "b", "c"] or [a, b, c]
    cleaned = options_str.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        inner = cleaned[1:-1]
        parts = [p.strip().strip('"').strip("'") for p in inner.split(",")]
        return [p for p in parts if p]
    # Handle comma-separated
    if "," in cleaned:
        return [p.strip().strip('"').strip("'") for p in cleaned.split(",")]
    # Single value
    if cleaned:
        return [cleaned]
    return []


# Operation → validator mapping
VALIDATORS = {
    "decide": validate_decide,
    "analyze": validate_text_response,
    "generate": validate_text_response,
    "reason": validate_text_response,
}


class ResponseValidator:
    """
    Validates LLM responses and retries on failure.

    Usage:
        validator = ResponseValidator(llm_call_fn, max_retries=3)
        result = validator.call_validated("decide", data)
        # result.valid is True and result.value is clean
    """

    def __init__(self, llm_call: Callable, max_retries: int = 3):
        self.llm_call = llm_call  # fn(operation, data) → str
        self.max_retries = max_retries
        self.retry_log: List[Dict] = []

    def call_validated(self, operation: str, data: Dict) -> ValidationResult:
        """
        Call the LLM and validate the response.
        Retries with feedback if validation fails.
        """
        validator = VALIDATORS.get(operation, validate_text_response)
        last_error = ""

        for attempt in range(1, self.max_retries + 1):
            # Build data with retry feedback if this isn't the first attempt
            call_data = dict(data)
            if last_error and attempt > 1:
                call_data["_retry_feedback"] = (
                    f"Your previous response was invalid: {last_error}. "
                    f"Please try again following the format instructions exactly."
                )
                if attempt == self.max_retries:
                    # Last attempt — be very explicit
                    call_data["_retry_feedback"] += (
                        f" This is the final attempt. "
                        f"Respond with ONLY the required value, nothing else."
                    )

            # Call LLM
            response = self.llm_call(operation, call_data)

            # Validate
            result = validator(response, data)
            result.attempts = attempt

            self.retry_log.append({
                "attempt": attempt,
                "operation": operation,
                "response": response[:200],
                "valid": result.valid,
                "error": result.error,
            })

            if result.valid:
                return result

            last_error = result.error

        # All retries exhausted
        return ValidationResult(
            valid=False,
            raw_response=response,
            error=f"Failed after {self.max_retries} attempts. Last error: {last_error}",
            attempts=self.max_retries,
        )

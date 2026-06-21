"""
Synsema Flat Syntax — Document-style alternative syntax.

Instead of indentation-based blocks:

    task process_order(order)
        when amount of order > 1000
            approve "Large order"
        otherwise
            log "Small order"

Write document-style:

    task process_order(order):
        When amount of order > 1000, approve "Large order".
        Otherwise, log "Small order".
        Then give "processed".

Rules:
    - Each step is one line ending with a period.
    - Conditions use commas: "When X, do Y."
    - Sequential steps: "Then do Z."
    - Alternatives: "Otherwise, do W."
    - No indentation required for flow control.
    - Blocks end with "end" or a blank line.

This module translates flat syntax to standard Synsema source,
which then goes through the normal lexer/parser pipeline.
"""

import re
from typing import List, Optional


class FlatSyntaxTranslator:
    """
    Translates flat/document-style syntax into standard Synsema.

    This is a pre-processor: flat syntax → standard syntax → lexer → parser.
    """

    def translate(self, source: str) -> str:
        """Translate flat syntax to standard Synsema."""
        lines = source.split("\n")
        output_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith("--"):
                output_lines.append(line)
                i += 1
                continue

            # Task definition with colon
            task_match = re.match(r'^(task\s+\w+\([^)]*\))\s*:', stripped)
            if task_match:
                output_lines.append(task_match.group(1))
                i += 1
                body_lines = self._collect_body(lines, i)
                for bl in body_lines:
                    translated = self._translate_statement(bl)
                    output_lines.extend(self._indent_block(translated, "    "))
                i += len(body_lines)
                if i < len(lines) and lines[i].strip().lower() == "end":
                    i += 1
                continue

            # Agent definition with colon
            agent_match = re.match(r'^(agent\s+\w+)\s*:', stripped)
            if agent_match:
                output_lines.append(agent_match.group(1))
                i += 1
                body_lines = self._collect_body(lines, i)
                for bl in body_lines:
                    translated = self._translate_statement(bl)
                    output_lines.extend(self._indent_block(translated, "    "))
                i += len(body_lines)
                if i < len(lines) and lines[i].strip().lower() == "end":
                    i += 1
                continue

            # Type definition with colon
            type_match = re.match(r'^(type\s+\w+)\s*:', stripped)
            if type_match:
                output_lines.append(type_match.group(1))
                i += 1
                body_lines = self._collect_body(lines, i)
                for bl in body_lines:
                    output_lines.append("    " + bl.strip().rstrip("."))
                i += len(body_lines)
                if i < len(lines) and lines[i].strip().lower() == "end":
                    i += 1
                continue

            # Regular statement
            translated = self._translate_statement(stripped)
            output_lines.append(translated)
            i += 1

        return "\n".join(output_lines)

    def _indent_block(self, text: str, prefix: str) -> List[str]:
        """Indent all lines of a translated statement."""
        lines = text.split("\n")
        return [prefix + line for line in lines]

    def _collect_body(self, lines: List[str], start: int) -> List[str]:
        """Collect body lines until 'end', blank line, or unindented line."""
        body = []
        i = start
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if stripped.lower() == "end":
                break
            if stripped == "" and body:
                break
            if stripped:
                body.append(stripped)
            i += 1
        return body

    def _translate_statement(self, line: str) -> str:
        """Translate a single flat-syntax statement to standard Synsema."""
        # Remove trailing period
        line = line.rstrip(".")
        stripped = line.strip()

        if not stripped:
            return ""

        # "When X, do Y." → when X\n    Y
        when_match = re.match(r'^[Ww]hen\s+(.+?),\s*(.+)$', stripped)
        if when_match:
            condition = when_match.group(1)
            action = self._translate_statement(when_match.group(2))
            return f"when {condition}\n    {action}"

        # "Otherwise when X, do Y." → otherwise when X\n    Y
        ow_match = re.match(r'^[Oo]therwise\s+when\s+(.+?),\s*(.+)$', stripped)
        if ow_match:
            condition = ow_match.group(1)
            action = self._translate_statement(ow_match.group(2))
            return f"otherwise when {condition}\n    {action}"

        # "Otherwise, do Y." → otherwise\n    Y
        else_match = re.match(r'^[Oo]therwise,?\s*(.+)$', stripped)
        if else_match:
            action = self._translate_statement(else_match.group(1))
            return f"otherwise\n    {action}"

        # "Then X" → X (sequential, just strip "then")
        then_match = re.match(r'^[Tt]hen\s+(.+)$', stripped)
        if then_match:
            return self._translate_statement(then_match.group(1))

        # "For each X in Y, do Z." → each X in Y\n    Z
        each_match = re.match(r'^[Ff]or each\s+(\w+)\s+in\s+(.+?),\s*(.+)$', stripped)
        if each_match:
            var = each_match.group(1)
            collection = each_match.group(2)
            action = self._translate_statement(each_match.group(3))
            return f"each {var} in {collection}\n    {action}"

        # Normalize capitalized keywords to lowercase
        keyword_map = {
            "Let ": "let ", "Set ": "set ", "Give ": "give ",
            "Show ": "show ", "Log ": "log ", "Stop": "stop",
            "Approve ": "approve ", "Confirm ": "confirm ",
            "Share ": "share ", "Observe ": "observe ",
            "Require ": "require ", "Spawn ": "spawn ",
        }
        for cap, low in keyword_map.items():
            if stripped.startswith(cap):
                stripped = low + stripped[len(cap):]
                break

        return stripped


def translate_flat(source: str) -> str:
    """Convenience function: translate flat syntax to standard Synsema."""
    return FlatSyntaxTranslator().translate(source)

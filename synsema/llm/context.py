"""
Synsema LLM Context Builder.

When the language calls the LLM (reason, decide, analyze, generate),
it should send the FULL context, not just the raw data. The LLM needs:

    - What the program is trying to do (intent)
    - What variables are in scope and their values
    - What rules the owner set
    - What the agent has learned (memory)
    - What step of the task we're on (progress)
    - What capabilities are available
    - What trace we're inside of

This turns a generic LLM call into an INFORMED decision.

Without context:
    "Choose between refund and replace given {issue: broken item}"

With context:
    "You are an agent processing customer support tickets.
     Intent: Handle support tickets and resolve issues.
     Current step: evaluate_action (3 of 5).
     Owner rules: max_refund <= 200, prefer replacement over refund.
     Memory: Last 3 similar cases were resolved with replacement.
     Customer: Alice (loyal, 5 previous orders).
     Choose between refund and replace given {issue: broken item}"
"""

from typing import Dict, List, Any, Optional


class LLMContext:
    """
    Collects and formats context for LLM calls.

    Attached to the interpreter and engine, it gathers
    all available context at the moment of an LLM call.
    """

    def __init__(self):
        self.intent: Optional[str] = None
        self.active_trace: Optional[str] = None
        self.current_step: Optional[str] = None
        self.progress_summary: Optional[str] = None
        self.rules: List[Dict] = []
        self.recent_memory: List[Dict] = []
        self.variables: Dict[str, str] = {}
        self.capabilities: List[str] = []
        self.agent_name: Optional[str] = None
        self.custom_context: Dict[str, str] = {}

    def set_intent(self, intent: str):
        self.intent = intent

    def set_trace(self, trace_name: str):
        self.active_trace = trace_name

    def set_progress(self, step: str, summary: str):
        self.current_step = step
        self.progress_summary = summary

    def set_rules(self, rules: List[Dict]):
        self.rules = rules

    def set_memory(self, entries: List[Dict]):
        self.recent_memory = entries

    def set_variables(self, variables: Dict[str, str]):
        self.variables = variables

    def set_capabilities(self, caps: List[str]):
        self.capabilities = caps

    def build_system_prompt(self) -> str:
        """
        Build a system-level prompt with all available context.

        This goes as a system message or preamble before the actual request.
        """
        parts = []

        parts.append("You are the reasoning engine for a Synsema agent.")

        if self.agent_name:
            parts.append(f"Agent name: {self.agent_name}")

        if self.intent:
            parts.append(f"Program intent: {self.intent}")

        if self.current_step:
            step_info = f"Current task step: {self.current_step}"
            if self.progress_summary:
                step_info += f" ({self.progress_summary})"
            parts.append(step_info)

        if self.active_trace:
            parts.append(f"Inside trace block: {self.active_trace}")

        if self.rules:
            rules_text = "Owner rules in effect:\n"
            for r in self.rules:
                level = r.get("level", "")
                desc = r.get("description", "")
                rules_text += f"  [{level}] {desc}\n"
            parts.append(rules_text.rstrip())

        if self.recent_memory:
            mem_text = "Relevant agent memory:\n"
            for m in self.recent_memory[:5]:
                cat = m.get("category", "")
                content = m.get("content", "")
                mem_text += f"  [{cat}] {content}\n"
            parts.append(mem_text.rstrip())

        if self.variables:
            # Filter out builtins and tasks, show only user data
            user_vars = {
                k: v for k, v in self.variables.items()
                if not v.startswith("SynValue(task:") and not v.startswith("builtin:")
                and not v.startswith("task ")
            }
            if user_vars:
                vars_text = "Visible variables:\n"
                for k, v in list(user_vars.items())[:15]:
                    vars_text += f"  {k} = {v}\n"
                parts.append(vars_text.rstrip())

        if self.capabilities:
            parts.append(f"Available capabilities: {', '.join(self.capabilities)}")

        parts.append(
            "Respond concisely and directly. "
            "When choosing between options, respond with ONLY the chosen option. "
            "When analyzing, be structured and actionable. "
            "Respect all owner rules."
        )

        return "\n\n".join(parts)

    def enrich_request_data(self, operation: str, data: Dict) -> Dict:
        """
        Enrich a request's data dict with context.

        This adds context fields to the data so the prompt builder
        can include them.
        """
        enriched = dict(data)
        enriched["_context"] = {
            "intent": self.intent,
            "trace": self.active_trace,
            "step": self.current_step,
            "rules": self.rules,
            "memory": self.recent_memory,
            "agent": self.agent_name,
        }
        return enriched


def build_contextual_prompt(operation: str, data: Dict,
                            context: LLMContext) -> str:
    """
    Build a complete prompt with context for an LLM operation.

    This replaces the generic _build_prompt in providers.
    """
    system = context.build_system_prompt() if context else ""

    if operation == "reason":
        subject = data.get("subject", "")
        user_context = data.get("context", {})
        prompt = f"Reason about: {subject}\n"
        if user_context:
            prompt += "\nProvided context:\n"
            for k, v in user_context.items():
                prompt += f"  {k}: {v}\n"
        prompt += "\nProvide a clear, structured analysis."

    elif operation == "decide":
        options = data.get("options", "")
        given = data.get("given", "")
        prompt = f"Given: {given}\n\n"
        prompt += f"Choose the best option from: {options}\n"
        prompt += "Respond with ONLY the chosen option, nothing else."

    elif operation == "analyze":
        data_str = data.get("data", "")
        objective = data.get("objective", "")
        prompt = f"Data to analyze:\n{data_str}\n\n"
        prompt += f"Objective: {objective}\n"
        prompt += "Provide a concise, actionable analysis."

    elif operation == "generate":
        target = data.get("target", "")
        given = data.get("given", "")
        params = data.get("parameters", {})
        prompt = f"Generate: {target}\n"
        if given:
            prompt += f"\nBased on: {given}\n"
        if params:
            prompt += "\nParameters:\n"
            for k, v in params.items():
                prompt += f"  {k}: {v}\n"

    else:
        prompt = str(data)

    if system:
        return f"{system}\n\n---\n\n{prompt}"
    return prompt

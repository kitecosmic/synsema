"""
Syntecnia Runtime Engine.

The engine is the top-level orchestrator that ties together:
- Lexer → Parser → Interpreter
- LLM provider configuration
- Capability management
- Human interaction handling
- Execution tracing and logging

This is what you interact with when you run a .syn file.
"""

import json
import time
from typing import Optional, Callable, Dict, Any, List
from pathlib import Path

from ..core.lexer import Lexer, LexerError
from ..core.parser import Parser, ParseError
from ..core.interpreter import Interpreter, RuntimeError as SynRuntimeError
from ..core import ast_nodes as ast
from ..core.types import SynValue, syn_nothing
from ..capabilities.model import (
    CapabilitySet, Capability, CapabilityType, CapabilityViolation,
    parse_capability,
)
from ..capabilities.enforcer import SecureOperations
from ..capabilities.builtins import register_secure_builtins
from ..capabilities.intent import IntentEnforcer, ActionCategory
from ..llm.provider import LLMProvider, LLMRequest, create_provider
from .error_reporter import ErrorReporter, ErrorDiagnostic
from .recovery import RecoveryProtocol
from ..agents.swarm import AgentSwarm
from ..llm.context import LLMContext, build_contextual_prompt
from ..llm.validator import ResponseValidator
from ..agents.progress import ProgressManager
from ..agents.memory import AgentMemory
from ..agents.builtins import register_agent_builtins
from ..stdlib.http import register_http_builtins
from ..stdlib.database import DatabaseManager, register_database_builtins
from ..stdlib.cron import CronScheduler, register_cron_builtins
from .persistence import StatePersistence


class ExecutionResult:
    """Result of running a Syntecnia program."""
    def __init__(self):
        self.value: SynValue = syn_nothing()
        self.logs: List[Dict] = []
        self.trace: List = []
        self.errors: List[str] = []
        self.duration_ms: float = 0
        self.success: bool = True
        self.output: List[str] = []
        self.diagnostics: List[ErrorDiagnostic] = []  # rich error info

    def summary(self) -> str:
        status = "OK" if self.success else "FAILED"
        lines = [
            f"[{status}] Duration: {self.duration_ms:.1f}ms",
            f"  Result: {self.value}",
        ]
        if self.errors:
            lines.append(f"  Errors: {len(self.errors)}")
            for e in self.errors:
                lines.append(f"    - {e}")
        if self.logs:
            lines.append(f"  Log entries: {len(self.logs)}")
        return "\n".join(lines)


class SyntecniaEngine:
    """
    Main runtime engine for Syntecnia.

    Usage:
        engine = SyntecniaEngine()
        result = engine.run_file("program.syn")
        result = engine.run_source('let x be 42\\nshow x')
    """

    def __init__(self, secure: bool = False):
        self.interpreter = Interpreter()
        self.llm_provider: Optional[Callable] = None
        self.human_handler: Optional[Callable] = None
        self._output_buffer: List[str] = []
        self.secure = secure

        # Capability system
        self.capabilities = CapabilitySet(name="program")
        self.secure_ops = SecureOperations(self.capabilities)

        # In secure mode, stdout requires a capability.
        # In normal mode, grant stdout by default for convenience.
        if not secure:
            self.capabilities.grant(Capability(CapabilityType.STDOUT))
            self.capabilities.grant(Capability(CapabilityType.TIME))

        # Intent enforcement
        self.intent_enforcer = IntentEnforcer()
        self.interpreter.intent_enforcer = self.intent_enforcer

        # Wire intent enforcer to secure operations
        self.secure_ops.intent_enforcer = self.intent_enforcer

        # Capability scoping for tasks
        self._cap_stack: List[CapabilitySet] = []
        self.interpreter._capability_scope_callback = self._capability_scope

        # Wire require statements to the real CapabilitySet
        self.interpreter._grant_capability = lambda name, scope: self.grant_capability(name, scope)

        # LLM context builder
        self.llm_context = LLMContext()

        # Error reporter and recovery
        self.error_reporter = ErrorReporter()
        self.recovery_protocol = RecoveryProtocol(
            error_reporter=self.error_reporter,
            output_callback=self._on_output,
        )

        # Agent swarm (real threading)
        self.swarm = AgentSwarm()
        self._wire_swarm()

        # Agent systems: progress, memory, rules
        self.progress_manager = ProgressManager()
        self.agent_memory = AgentMemory()

        # Database and cron managers
        self.db_manager = DatabaseManager()
        self.cron_scheduler = CronScheduler()

        # State persistence (survives restarts)
        self.persistence: Optional[StatePersistence] = None

        # Register secure builtins (fetch, read_file, etc.)
        register_secure_builtins(self.interpreter.global_env, self.secure_ops)

        # Register agent builtins (progress, memory, rules)
        register_agent_builtins(
            self.interpreter.global_env,
            self.progress_manager,
            self.agent_memory,
        )

        # Register stdlib builtins (http, database, cron)
        register_http_builtins(self.interpreter.global_env)
        register_database_builtins(self.interpreter.global_env, self.db_manager)
        register_cron_builtins(self.interpreter.global_env, self.cron_scheduler, self.interpreter)

        # Wire up callbacks
        self.interpreter.output_callback = self._on_output
        self.interpreter.llm_callback = self._on_llm
        self.interpreter.human_callback = self._on_human

    def _wire_swarm(self):
        """Connect the interpreter to the real swarm for agent operations."""
        import threading as _threading
        from ..agents.swarm import AgentInfo, AgentState

        interp = self.interpreter
        swarm = self.swarm

        def swarm_spawn(agent_name, body, parent_env, spawn_args):
            """Spawn an agent in a real thread."""
            instance_id = f"{agent_name}_{len(swarm.agents)}"

            def run_agent():
                from ..core.interpreter import Interpreter, Environment

                agent_interp = Interpreter()
                agent_interp.output_callback = interp.output_callback
                agent_interp.llm_callback = interp.llm_callback
                agent_interp.human_callback = interp.human_callback

                # Wire agent's swarm operations
                agent_interp._swarm_share = lambda k, v: swarm.blackboard.write(k, v, agent=instance_id)
                agent_interp._swarm_observe = lambda k: swarm.blackboard.read(k, agent=instance_id)
                agent_interp._swarm_signal = lambda name, data: swarm.signal(name, instance_id, data)

                def agent_wait_for(name, timeout=30):
                    """Wait for signal, setting WAITING state while blocked."""
                    if instance_id in swarm.agents:
                        swarm.agents[instance_id].state = AgentState.WAITING
                    sig = swarm.wait_for_signal(name, timeout=timeout)
                    if instance_id in swarm.agents:
                        swarm.agents[instance_id].state = AgentState.WORKING
                    if sig and sig.data:
                        return sig.data
                    return None

                agent_interp._swarm_wait_for = agent_wait_for

                agent_env = Environment(parent=parent_env, name=f"agent:{instance_id}")
                for key, val in spawn_args.items():
                    agent_env.set(key, val)

                try:
                    swarm.agents[instance_id].state = AgentState.WORKING
                    agent_interp._exec_block(body, agent_env)
                    swarm.agents[instance_id].state = AgentState.DONE
                except Exception as e:
                    swarm.agents[instance_id].state = AgentState.ERROR
                    swarm.agents[instance_id].error = str(e)
                    # Wake up any agents waiting for signals from this agent.
                    # Without this, a waiter hangs for 30s on a dead agent.
                    swarm.signal(f"__agent_error:{instance_id}", instance_id)
                finally:
                    import time as _time
                    swarm.agents[instance_id].finished_at = _time.time()

            import time as _time
            info = AgentInfo(
                name=instance_id, state=AgentState.STARTING,
                started_at=_time.time(),
            )
            swarm.agents[instance_id] = info
            thread = _threading.Thread(target=run_agent, name=instance_id, daemon=True)
            swarm._threads[instance_id] = thread
            thread.start()
            return instance_id

        def main_wait_for(name, timeout=30):
            sig = swarm.wait_for_signal(name, timeout=timeout)
            if sig and sig.data:
                return sig.data
            return None

        # Wire interpreter callbacks to swarm
        interp._swarm_spawn = swarm_spawn
        interp._swarm_share = lambda k, v: swarm.blackboard.write(k, v, agent="main")
        interp._swarm_observe = lambda k: swarm.blackboard.read(k, agent="main")
        interp._swarm_signal = lambda name, data: swarm.signal(name, "main", data)
        interp._swarm_wait_for = main_wait_for

    def configure_llm_provider(self, provider_name: str, **kwargs):
        """
        Configure LLM provider by name.

        Examples:
            engine.configure_llm_provider("anthropic", api_key="sk-...")
            engine.configure_llm_provider("ollama", model="llama3")
            engine.configure_llm_provider("mock", responses={"decide": "approve"})
        """
        provider = create_provider(provider_name, **kwargs)
        self._llm_provider_instance = provider

        def llm_callback(operation: str, data: dict) -> str:
            request = LLMRequest(operation=operation, data=data)
            response = provider.call(request)
            return response.content

        self.llm_provider = llm_callback
        self.interpreter.llm_callback = self._on_llm

    def grant_capability(self, name: str, scope: str = None):
        """Grant a capability to the program."""
        cap = parse_capability(name, scope)
        self.capabilities.grant(cap)

    def deny_capability(self, name: str, scope: str = None):
        """Explicitly deny a capability."""
        cap = parse_capability(name, scope)
        self.capabilities.deny(cap)

    def get_audit_report(self) -> str:
        """Get the capability audit report."""
        report = self.capabilities.get_audit_report()
        report += "\n\n" + self.intent_enforcer.get_report()
        return report

    def set_intent_strict(self, strict: bool = True):
        """Set whether intent violations block execution or just warn."""
        self.intent_enforcer.strict = strict

    def _capability_scope(self, action: str, task_name: str, data):
        """
        Push/pop capability scopes for task-level security.

        When a task declares `require net("api.example.com")`, it runs
        in a sandbox that ONLY has that capability. The task cannot
        access anything the program can — only what it declared.
        """
        if action == "push":
            # data = list of (cap_name, scope) tuples
            task_caps = self.capabilities.create_sandbox(f"task:{task_name}")
            for cap_name, scope in data:
                cap = parse_capability(cap_name, scope)
                task_caps.grant(cap)
            # Always allow stdout and time in tasks
            task_caps.grant(Capability(CapabilityType.STDOUT))
            task_caps.grant(Capability(CapabilityType.TIME))

            # Save current and switch
            saved = self.secure_ops.capabilities
            self._cap_stack.append(saved)
            self.secure_ops.capabilities = task_caps
            return saved
        elif action == "pop":
            # data = saved capabilities
            self.secure_ops.capabilities = data
            if self._cap_stack:
                self._cap_stack.pop()

    def configure_llm(self, provider: Callable):
        """
        Set the LLM provider callback.

        The callback receives (operation, data) where operation is one of:
        'reason', 'decide', 'analyze', 'generate'
        """
        self.llm_provider = provider

    def configure_human(self, handler: Callable):
        """
        Set the human interaction handler.

        The handler receives (action, message) where action is one of:
        'approve', 'confirm', 'ask', 'show'
        """
        self.human_handler = handler

    def _on_output(self, text: str):
        self._output_buffer.append(text)

    def _on_llm(self, operation: str, data: dict) -> str:
        # Gather current context for the LLM
        self._update_llm_context()

        if self.llm_provider:
            def raw_call(op, call_data):
                """Raw LLM call that builds contextual prompt."""
                # Include retry feedback in prompt if present
                retry_feedback = call_data.pop("_retry_feedback", None)

                if hasattr(self, '_llm_provider_instance') and self._llm_provider_instance:
                    from ..llm.provider import LLMRequest
                    prompt = build_contextual_prompt(op, call_data, self.llm_context)
                    if retry_feedback:
                        prompt += f"\n\nIMPORTANT: {retry_feedback}"
                    call_data["_contextual_prompt"] = prompt
                    request = LLMRequest(operation=op, data=call_data)
                    response = self._llm_provider_instance.call(request)
                    return response.content
                return self.llm_provider(op, call_data)

            # Use validator for validated calls
            validator = ResponseValidator(raw_call, max_retries=3)
            result = validator.call_validated(operation, data)

            if result.valid:
                return result.value

            # Validation failed after retries — log and return raw
            self._output_buffer.append(
                f"[WARN] LLM response validation failed after {result.attempts} attempts: {result.error}"
            )
            return result.raw_response

        return f"[LLM:{operation} not configured]"

    def _update_llm_context(self):
        """Gather all available context for the next LLM call."""
        # Intent
        if self.intent_enforcer.intent:
            self.llm_context.set_intent(self.intent_enforcer.intent.description)

        # Variables (filter to user-defined only)
        env_dump = self.interpreter.global_env.dump()
        user_vars = {}
        for k, v in env_dump.items():
            s = str(v)
            if not s.startswith("SynValue(task:") and "builtin:" not in s:
                user_vars[k] = s
        self.llm_context.set_variables(user_vars)

        # Active trace
        if self.error_reporter.active_traces:
            self.llm_context.set_trace(self.error_reporter.active_traces[-1])

        # Rules
        active_rules = self.agent_memory.get_rules()
        self.llm_context.set_rules([r.to_dict() for r in active_rules])

        # Recent memory (last 5 entries)
        recent = self.agent_memory.recall(limit=5)
        self.llm_context.set_memory([{
            "category": e.category.value,
            "content": e.content,
        } for e in recent])

        # Progress
        for task_name, progress in self.progress_manager.tasks.items():
            current = progress.current_step()
            if current:
                self.llm_context.set_progress(
                    current.name,
                    progress.status_summary,
                )
                break

        # Capabilities
        caps = [str(c) for c in self.capabilities.granted]
        self.llm_context.set_capabilities(caps)

    def _on_human(self, action: str, message: str) -> Any:
        if self.human_handler:
            return self.human_handler(action, message)
        # Default: auto-approve, auto-confirm
        if action in ("approve", "confirm"):
            return True
        return ""

    def run_source(self, source: str, filename: str = "<stdin>") -> ExecutionResult:
        """Run Syntecnia source code string."""
        result = ExecutionResult()
        self._output_buffer = []
        start = time.perf_counter()

        # Auto-enable persistence for named files
        if filename != "<stdin>" and not self.persistence:
            from pathlib import Path
            prog_name = Path(filename).stem
            self.persistence = StatePersistence(program_name=prog_name)
            self.persistence.load_into(self.agent_memory, self.progress_manager)

        # Load source for error context
        self.error_reporter.load_source(filename, source)

        # Track intent for error reporter
        if self.intent_enforcer.intent:
            self.error_reporter.set_intent(self.intent_enforcer.intent.description)

        # Wire recovery protocol's human callback
        self.recovery_protocol.human_callback = self._on_human

        try:
            # Lex
            lexer = Lexer(source, filename)
            tokens = lexer.tokenize_filtered()

            # Parse
            parser = Parser(tokens, filename)
            program = parser.parse()

            # Pre-scan: execute intent/require declarations at the TOP,
            # then freeze intent before running the rest.
            preamble = []
            body = []
            from ..core import ast_nodes as astn
            in_preamble = True
            for stmt in program.statements:
                if in_preamble and isinstance(stmt, (astn.IntentDeclaration, astn.RequireStatement)):
                    preamble.append(stmt)
                else:
                    in_preamble = False
                    body.append(stmt)

            # Execute preamble (intent + require declarations)
            for stmt in preamble:
                self.interpreter._exec(stmt, self.interpreter.global_env)

            # Freeze intent
            if self.intent_enforcer.intent:
                self.intent_enforcer.freeze_intent()
                self.interpreter._intent_frozen = True
                self.error_reporter.set_intent(self.intent_enforcer.intent.description)

            # Execute body
            program.statements = body
            result.value = self.interpreter.execute(program)
            result.logs = self.interpreter.logs.copy()
            result.trace = self.interpreter.trace.copy()

        except LexerError as e:
            result.success = False
            result.errors.append(f"Lexer error: {e}")
        except ParseError as e:
            result.success = False
            result.errors.append(f"Parse error: {e}")
        except (SynRuntimeError, CapabilityViolation) as e:
            result.success = False
            # Build rich diagnostic
            diag = self.error_reporter.build_diagnostic(
                e, env=self.interpreter.global_env
            )
            result.diagnostics.append(diag)
            result.errors.append(f"Runtime error: {e}")
        except Exception as e:
            result.success = False
            result.errors.append(f"Internal error: {type(e).__name__}: {e}")

        result.duration_ms = (time.perf_counter() - start) * 1000
        result.output = self._output_buffer.copy()

        # Auto-save state after execution
        if self.persistence:
            self.persistence.save_from(self.agent_memory, self.progress_manager)

        return result

    def run_file(self, filepath: str) -> ExecutionResult:
        """Run a .syn file."""
        path = Path(filepath)
        if not path.exists():
            result = ExecutionResult()
            result.success = False
            result.errors.append(f"File not found: {filepath}")
            return result

        source = path.read_text(encoding="utf-8")
        return self.run_source(source, filename=str(path))

    def repl(self):
        """Start an interactive REPL."""
        print(f"Syntecnia v0.1.0 — Interactive Mode")
        print(f"Type 'exit' to quit, 'env' to see variables, 'trace' to see trace.\n")

        while True:
            try:
                line = input("syn> ")
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye.")
                break

            line = line.strip()
            if not line:
                continue
            if line == "exit":
                break
            if line == "env":
                for name, val in self.interpreter.global_env.dump().items():
                    print(f"  {name} = {val}")
                continue
            if line == "trace":
                for entry in self.interpreter.trace:
                    dur = f" ({entry.duration_ms:.1f}ms)" if entry.duration_ms else ""
                    print(f"  {entry.name}{dur} at {entry.location}")
                continue
            if line == "logs":
                for log in self.interpreter.logs[-20:]:
                    print(f"  {log}")
                continue
            if line == "audit":
                print(self.get_audit_report())
                continue
            if line == "caps":
                for cap in self.capabilities.granted:
                    print(f"  + {cap}")
                for cap in self.capabilities.denied:
                    print(f"  - {cap}")
                continue

            # Multi-line input: if line ends with ':', read indented block
            if line.endswith(":"):
                # Actually, we handle blocks via indentation
                # For REPL, collect lines until empty line
                lines = [line]
                while True:
                    try:
                        cont = input("...  ")
                    except (EOFError, KeyboardInterrupt):
                        break
                    if cont.strip() == "":
                        break
                    lines.append(cont)
                line = "\n".join(lines)

            result = self.run_source(line)
            if result.output:
                for out in result.output:
                    print(out)
            if result.errors:
                for err in result.errors:
                    print(f"  ERROR: {err}")
            elif result.value and str(result.value) != "nothing":
                print(f"  → {result.value}")

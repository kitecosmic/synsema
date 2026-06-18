"""
Syntecnia Agent Builtins — Built-in tasks for progress, memory, and rules.

These tasks are available to every Syntecnia program:

    -- Progress tracking
    let job be create_progress("sync", ["fetch", "validate", "update"])
    start_step(job, "fetch")
    complete_step(job, "fetch", "fetched 50 items")
    let where be resume_point(job)
    show progress_display(job)

    -- Memory
    remember("preference", "Customer prefers formal tone", ["communication"])
    let prefs be recall("preference", ["communication"])
    forget(entry_id)

    -- Rules
    add_rule("max_discount", "must", "discount <= 0.20", "pricing")
    let violations be check_rules("pricing", {"discount": 0.25})
    let rules be get_rules("pricing")
"""

from typing import List
from ..core.types import (
    SynValue, BuiltinTask,
    syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
    SynText, SynList, SynMap, SynTask,
)
from .progress import ProgressManager
from .memory import AgentMemory


def register_agent_builtins(env, progress_mgr: ProgressManager,
                            memory: AgentMemory):
    """Register progress, memory, and rule builtins."""

    # ===== Progress =====

    def _create_progress(args: List[SynValue]) -> SynValue:
        """create_progress(task_name, [step_names])"""
        task_name = str(args[0].raw)
        step_names = [str(s) for s in args[1].raw] if len(args) > 1 else []
        progress = progress_mgr.create(task_name, step_names)
        return syn_text(task_name)

    def _start_step(args: List[SynValue]) -> SynValue:
        """start_step(task_name, step_name)"""
        progress_mgr.start_step(str(args[0].raw), str(args[1].raw))
        return syn_bool(True)

    def _complete_step(args: List[SynValue]) -> SynValue:
        """complete_step(task_name, step_name, result?)"""
        result = str(args[2].raw) if len(args) > 2 else None
        progress_mgr.complete_step(str(args[0].raw), str(args[1].raw), result)
        return syn_bool(True)

    def _fail_step(args: List[SynValue]) -> SynValue:
        """fail_step(task_name, step_name, error?)"""
        error = str(args[2].raw) if len(args) > 2 else None
        progress_mgr.fail_step(str(args[0].raw), str(args[1].raw), error)
        return syn_bool(True)

    def _resume_point(args: List[SynValue]) -> SynValue:
        """resume_point(task_name) → step name or nothing"""
        point = progress_mgr.get_resume_point(str(args[0].raw))
        return syn_text(point) if point else syn_nothing()

    def _progress_display(args: List[SynValue]) -> SynValue:
        """progress_display(task_name) → formatted string"""
        task_name = str(args[0].raw)
        progress = progress_mgr.tasks.get(task_name)
        if not progress:
            return syn_text(f"No progress for '{task_name}'")
        return syn_text(progress.format_display())

    def _progress_percent(args: List[SynValue]) -> SynValue:
        """progress_percent(task_name) → number"""
        task_name = str(args[0].raw)
        progress = progress_mgr.tasks.get(task_name)
        if not progress:
            return syn_number(0)
        return syn_number(progress.progress_percent)

    # ===== Memory =====

    def _remember(args: List[SynValue]) -> SynValue:
        """remember(category, content, tags?)"""
        from ..core.interpreter import RuntimeError as SynRuntimeError
        category = str(args[0].raw)
        content = str(args[1].raw)
        tags = []
        if len(args) > 2 and isinstance(args[2].type, SynList):
            tags = [str(t) for t in args[2].raw]
        try:
            entry = memory.remember(category, content, tags=tags)
        except ValueError as e:
            raise SynRuntimeError(str(e))
        return syn_text(entry.id)

    def _recall(args: List[SynValue]) -> SynValue:
        """recall(category?, tags?, search?) → list of entries"""
        category = str(args[0].raw) if len(args) > 0 and str(args[0].raw) != "nothing" else None
        tags = None
        if len(args) > 1 and isinstance(args[1].type, SynList):
            tags = [str(t) for t in args[1].raw]
        search = str(args[2].raw) if len(args) > 2 else None

        entries = memory.recall(category=category, tags=tags, search=search)
        result = []
        for e in entries:
            result.append(syn_map({
                "id": syn_text(e.id),
                "category": syn_text(e.category.value),
                "content": syn_text(e.content),
                "source": syn_text(e.source),
                "tags": syn_list([syn_text(t) for t in e.tags]),
            }))
        return syn_list(result)

    def _forget(args: List[SynValue]) -> SynValue:
        """forget(entry_id)"""
        memory.forget(str(args[0].raw))
        return syn_bool(True)

    # ===== Rules =====

    def _add_rule(args: List[SynValue]) -> SynValue:
        """add_rule(name, level, description, category?)"""
        name = str(args[0].raw)
        level = str(args[1].raw)
        description = str(args[2].raw)
        category = str(args[3].raw) if len(args) > 3 else ""
        # Extract condition from description if it contains an operator
        condition = None
        import re
        cond_match = re.search(r'(\w+\s*(?:<=|>=|<|>|==|!=)\s*[\d.]+)', description)
        if cond_match:
            condition = cond_match.group(1)
        memory.add_rule(name, level, description, condition=condition, category=category)
        return syn_bool(True)

    def _check_rules(args: List[SynValue]) -> SynValue:
        """check_rules(category?, context_map?) → list of violations"""
        category = str(args[0].raw) if len(args) > 0 else None
        context = {}
        if len(args) > 1 and isinstance(args[1].type, SynMap):
            for k, v in args[1].raw.items():
                try:
                    context[k] = float(v.raw) if hasattr(v, 'raw') else float(v)
                except (ValueError, TypeError):
                    context[k] = str(v.raw) if hasattr(v, 'raw') else str(v)

        violations = memory.check_rules(category=category, context=context)
        result = []
        for v in violations:
            result.append(syn_map({
                "rule": syn_text(v.rule.name),
                "level": syn_text(v.rule.level.value),
                "message": syn_text(str(v)),
            }))
        return syn_list(result)

    def _get_rules(args: List[SynValue]) -> SynValue:
        """get_rules(category?) → list of rules"""
        category = str(args[0].raw) if len(args) > 0 else None
        rules = memory.get_rules(category=category)
        result = []
        for r in rules:
            result.append(syn_map({
                "name": syn_text(r.name),
                "level": syn_text(r.level.value),
                "description": syn_text(r.description),
                "category": syn_text(r.category),
            }))
        return syn_list(result)

    def _memory_summary(args: List[SynValue]) -> SynValue:
        """memory_summary() → formatted text"""
        return syn_text(memory.format_summary())

    # Register all
    builtins = {
        # Progress
        "create_progress": BuiltinTask("create_progress", _create_progress),
        "start_step": BuiltinTask("start_step", _start_step, 2),
        "complete_step": BuiltinTask("complete_step", _complete_step),
        "fail_step": BuiltinTask("fail_step", _fail_step),
        "resume_point": BuiltinTask("resume_point", _resume_point, 1),
        "progress_display": BuiltinTask("progress_display", _progress_display, 1),
        "progress_percent": BuiltinTask("progress_percent", _progress_percent, 1),
        # Memory
        "remember": BuiltinTask("remember", _remember),
        "recall": BuiltinTask("recall", _recall),
        "forget_memory": BuiltinTask("forget_memory", _forget, 1),
        # Rules
        "add_rule": BuiltinTask("add_rule", _add_rule),
        "check_rules": BuiltinTask("check_rules", _check_rules),
        "get_rules": BuiltinTask("get_rules", _get_rules),
        "memory_summary": BuiltinTask("memory_summary", _memory_summary, 0),
    }

    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTask()))

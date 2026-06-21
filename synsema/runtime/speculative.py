"""
Synsema Speculative Execution — Reversible runtime.

Allows an agent to:
    - Fork the execution state
    - Try different approaches in parallel
    - Roll back if something fails
    - Compare outcomes before committing

This works like a database transaction or git branch:

    speculate
        -- try approach A
        set price to price * 0.8
        when profit < 0
            rollback  -- undo everything in this block
        otherwise
            commit    -- make changes permanent

    -- Or fork to try multiple approaches:
    let outcomes be fork 3
        -- branch 0: aggressive discount
        set price to price * 0.7
        -- branch 1: moderate discount
        set price to price * 0.9
        -- branch 2: no discount
        -- (no change)

Implementation:
    - Snapshot the environment (all variables)
    - Execute speculatively
    - On rollback: restore the snapshot
    - On commit: discard the snapshot
    - Side effects (I/O) are buffered during speculation
"""

from typing import Dict, List, Optional, Any, Tuple
from copy import deepcopy
from ..core.types import SynValue, syn_nothing, syn_list, syn_map, syn_text, syn_bool
from ..core.interpreter import Environment


class EnvironmentSnapshot:
    """A frozen snapshot of an environment for rollback."""

    def __init__(self, env: Environment):
        self.name = env.name
        self.bindings = self._deep_copy_bindings(env.bindings)
        self.parent_snapshot: Optional['EnvironmentSnapshot'] = None
        if env.parent:
            self.parent_snapshot = EnvironmentSnapshot(env.parent)

    def _deep_copy_bindings(self, bindings: Dict[str, SynValue]) -> Dict[str, SynValue]:
        """Deep copy all bindings, preserving SynValue structure."""
        result = {}
        for name, value in bindings.items():
            result[name] = self._copy_value(value)
        return result

    def _copy_value(self, value: SynValue) -> SynValue:
        """Copy a SynValue, handling nested structures."""
        try:
            return deepcopy(value)
        except:
            # Fallback for non-copyable values (tasks with closures)
            return value

    def restore(self, env: Environment):
        """Restore an environment from this snapshot."""
        env.bindings.clear()
        env.bindings.update(self._deep_copy_bindings(self.bindings))
        if self.parent_snapshot and env.parent:
            self.parent_snapshot.restore(env.parent)


class SpeculativeContext:
    """
    A speculative execution context.

    Captures state before speculation begins,
    buffers side effects, and provides commit/rollback.
    """

    def __init__(self, env: Environment, name: str = ""):
        self.name = name
        self.snapshot = EnvironmentSnapshot(env)
        self.env = env
        self.committed = False
        self.rolled_back = False
        self.buffered_output: List[str] = []
        self.buffered_blackboard: Dict[str, SynValue] = {}
        self.buffered_signals: List[Dict] = []

    def rollback(self):
        """Restore the environment to the snapshot state."""
        if self.committed:
            raise RuntimeError("Cannot rollback after commit")
        self.snapshot.restore(self.env)
        self.rolled_back = True
        self.buffered_output.clear()
        self.buffered_blackboard.clear()
        self.buffered_signals.clear()

    def commit(self):
        """Confirm the speculative changes — they become permanent."""
        if self.rolled_back:
            raise RuntimeError("Cannot commit after rollback")
        self.committed = True
        # Buffered side effects get released on commit


class SpeculativeEngine:
    """
    Manages speculative execution for the Synsema runtime.

    Usage:
        spec = SpeculativeEngine(interpreter)

        # Start speculation
        ctx = spec.begin(env, "try_discount")

        # ... execute code ...

        # If good:
        spec.commit(ctx)

        # If bad:
        spec.rollback(ctx)

        # Or fork:
        results = spec.fork(env, branches=[branch_a, branch_b])
    """

    def __init__(self):
        self.active_contexts: List[SpeculativeContext] = []
        self.history: List[Dict] = []

    def begin(self, env: Environment, name: str = "") -> SpeculativeContext:
        """Begin a speculative execution context."""
        ctx = SpeculativeContext(env, name)
        self.active_contexts.append(ctx)
        self.history.append({
            "action": "begin",
            "name": name,
        })
        return ctx

    def commit(self, ctx: SpeculativeContext):
        """Commit speculative changes."""
        ctx.commit()
        if ctx in self.active_contexts:
            self.active_contexts.remove(ctx)
        self.history.append({
            "action": "commit",
            "name": ctx.name,
        })

    def rollback(self, ctx: SpeculativeContext):
        """Rollback speculative changes."""
        ctx.rollback()
        if ctx in self.active_contexts:
            self.active_contexts.remove(ctx)
        self.history.append({
            "action": "rollback",
            "name": ctx.name,
        })

    def fork(self, env: Environment, branch_fns: list,
             interpreter=None) -> List[Tuple[SynValue, EnvironmentSnapshot]]:
        """
        Fork execution into multiple branches.

        Each branch gets a copy of the environment and runs independently.
        Returns list of (result, final_state) for each branch.

        The agent can then choose which branch's result to keep.
        """
        results = []

        for i, branch_fn in enumerate(branch_fns):
            # Create a fresh environment copy
            branch_env = Environment(parent=env.parent, name=f"fork:{i}")
            snapshot = EnvironmentSnapshot(env)

            # Copy bindings
            for name, value in env.bindings.items():
                try:
                    branch_env.bindings[name] = deepcopy(value)
                except:
                    branch_env.bindings[name] = value

            # Execute branch
            try:
                if interpreter and callable(branch_fn):
                    result = branch_fn(interpreter, branch_env)
                elif isinstance(branch_fn, list) and interpreter:
                    result = interpreter._exec_block(branch_fn, branch_env)
                else:
                    result = syn_nothing()
                final_state = EnvironmentSnapshot(branch_env)
                results.append((result, final_state))
            except Exception as e:
                results.append((syn_text(f"error: {e}"), snapshot))

        self.history.append({
            "action": "fork",
            "branches": len(branch_fns),
        })

        return results

    def choose_and_apply(self, env: Environment, results: list, index: int):
        """
        After forking, choose a branch result and apply it.

        This makes the chosen branch's state the "real" state.
        """
        if index < 0 or index >= len(results):
            raise ValueError(f"Invalid branch index: {index}")

        _, chosen_snapshot = results[index]
        chosen_snapshot.restore(env)

        self.history.append({
            "action": "choose",
            "branch": index,
        })

    @property
    def is_speculating(self) -> bool:
        return len(self.active_contexts) > 0

    def get_report(self) -> str:
        lines = ["Speculative Execution Report"]
        lines.append(f"  Active contexts: {len(self.active_contexts)}")
        lines.append(f"  History: {len(self.history)} events")
        for event in self.history:
            lines.append(f"    {event['action']}: {event.get('name', '')}")
        return "\n".join(lines)

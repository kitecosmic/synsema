"""
Synsema Task Progress Tracking.

Every agent knows where it is in its work:

    progress "sync_inventory"
        step "fetch_products" status "done"
        step "check_prices" status "in_progress"
        step "update_stock" status "pending"
        step "notify_team" status "pending"

If the agent crashes and restarts, it checks progress and resumes
from the last incomplete step — not from scratch.

Progress is:
    - Persistent (survives restarts)
    - Observable (other agents can see where you are)
    - Structured (not just a log, but a state machine)

Each step has:
    - name: what it's called
    - status: pending, in_progress, done, failed, skipped
    - started_at / finished_at: timestamps
    - result: what the step produced (optional)
    - error: why it failed (optional)
    - metadata: arbitrary data for the step
"""

import json
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class StepStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TaskStep:
    """A single step in a task."""
    name: str
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    retries: int = 0

    def start(self):
        self.status = StepStatus.IN_PROGRESS
        self.started_at = time.time()

    def complete(self, result: str = None):
        self.status = StepStatus.DONE
        self.finished_at = time.time()
        self.result = result

    def fail(self, error: str = None):
        self.status = StepStatus.FAILED
        self.finished_at = time.time()
        self.error = error

    def skip(self, reason: str = None):
        self.status = StepStatus.SKIPPED
        self.finished_at = time.time()
        self.metadata["skip_reason"] = reason

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at) * 1000
        return None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
            "retries": self.retries,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'TaskStep':
        step = cls(name=data["name"])
        step.status = StepStatus(data.get("status", "pending"))
        step.started_at = data.get("started_at")
        step.finished_at = data.get("finished_at")
        step.result = data.get("result")
        step.error = data.get("error")
        step.metadata = data.get("metadata", {})
        step.retries = data.get("retries", 0)
        return step


@dataclass
class TaskProgress:
    """
    Tracks the progress of a multi-step task.

    Usage in Synsema:
        let job be create_progress("sync_inventory", [
            "fetch", "validate", "update", "notify"
        ])

        start_step(job, "fetch")
        let data be fetch_products()
        complete_step(job, "fetch", "fetched 100 products")

        start_step(job, "validate")
        ...
    """
    task_name: str
    steps: List[TaskStep] = field(default_factory=list)
    created_at: float = 0.0
    agent_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()

    def add_step(self, name: str) -> TaskStep:
        step = TaskStep(name=name)
        self.steps.append(step)
        return step

    def get_step(self, name: str) -> Optional[TaskStep]:
        for step in self.steps:
            if step.name == name:
                return step
        return None

    def current_step(self) -> Optional[TaskStep]:
        """Get the currently in-progress step."""
        for step in self.steps:
            if step.status == StepStatus.IN_PROGRESS:
                return step
        return None

    def next_pending(self) -> Optional[TaskStep]:
        """Get the next pending step (for resumption)."""
        for step in self.steps:
            if step.status == StepStatus.PENDING:
                return step
        return None

    def resume_point(self) -> Optional[TaskStep]:
        """
        Find where to resume after a crash.

        If a step is IN_PROGRESS, resume there (it didn't finish).
        If all completed up to a point, resume at next PENDING.
        """
        for step in self.steps:
            if step.status == StepStatus.IN_PROGRESS:
                return step
            if step.status == StepStatus.FAILED:
                return step  # retry failed step
        return self.next_pending()

    @property
    def is_complete(self) -> bool:
        return all(
            s.status in (StepStatus.DONE, StepStatus.SKIPPED)
            for s in self.steps
        )

    @property
    def progress_percent(self) -> float:
        if not self.steps:
            return 100.0
        done = sum(1 for s in self.steps if s.status in (StepStatus.DONE, StepStatus.SKIPPED))
        return (done / len(self.steps)) * 100

    @property
    def status_summary(self) -> str:
        counts = {}
        for s in self.steps:
            counts[s.status.value] = counts.get(s.status.value, 0) + 1
        parts = [f"{v} {k}" for k, v in counts.items()]
        return f"{self.task_name}: {', '.join(parts)} ({self.progress_percent:.0f}%)"

    def format_display(self) -> str:
        """Human-readable progress display."""
        lines = [f"Task: {self.task_name} ({self.progress_percent:.0f}%)"]
        for step in self.steps:
            status_icon = {
                StepStatus.PENDING: "  ",
                StepStatus.IN_PROGRESS: ">>",
                StepStatus.DONE: "OK",
                StepStatus.FAILED: "XX",
                StepStatus.SKIPPED: "--",
            }[step.status]
            dur = f" ({step.duration_ms:.0f}ms)" if step.duration_ms else ""
            err = f" ERROR: {step.error}" if step.error else ""
            res = f" → {step.result}" if step.result else ""
            lines.append(f"  [{status_icon}] {step.name}{dur}{res}{err}")
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "task_name": self.task_name,
            "agent_name": self.agent_name,
            "created_at": self.created_at,
            "steps": [s.to_dict() for s in self.steps],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'TaskProgress':
        tp = cls(task_name=data["task_name"])
        tp.agent_name = data.get("agent_name", "")
        tp.created_at = data.get("created_at", 0)
        tp.steps = [TaskStep.from_dict(s) for s in data.get("steps", [])]
        tp.metadata = data.get("metadata", {})
        return tp


class ProgressManager:
    """
    Manages progress tracking for all tasks, with persistence.

    Saves progress to disk so agents can resume after crashes.
    """

    def __init__(self, persist_path: str = None):
        self.tasks: Dict[str, TaskProgress] = {}
        self.persist_path = persist_path

    def create(self, task_name: str, step_names: List[str],
               agent_name: str = "") -> TaskProgress:
        """Create a new task progress tracker."""
        # Check if resumable progress exists
        if task_name in self.tasks:
            existing = self.tasks[task_name]
            if not existing.is_complete:
                return existing  # resume existing

        progress = TaskProgress(task_name=task_name, agent_name=agent_name)
        for name in step_names:
            progress.add_step(name)
        self.tasks[task_name] = progress
        self._persist()
        return progress

    def start_step(self, task_name: str, step_name: str):
        progress = self.tasks.get(task_name)
        if not progress:
            raise ValueError(f"No task '{task_name}' tracked")
        step = progress.get_step(step_name)
        if not step:
            raise ValueError(f"No step '{step_name}' in task '{task_name}'")
        step.start()
        self._persist()

    def complete_step(self, task_name: str, step_name: str, result: str = None):
        progress = self.tasks.get(task_name)
        if not progress:
            raise ValueError(f"No task '{task_name}' tracked")
        step = progress.get_step(step_name)
        if not step:
            raise ValueError(f"No step '{step_name}' in task '{task_name}'")
        step.complete(result)
        self._persist()

    def fail_step(self, task_name: str, step_name: str, error: str = None):
        progress = self.tasks.get(task_name)
        if not progress:
            raise ValueError(f"No task '{task_name}' tracked")
        step = progress.get_step(step_name)
        if not step:
            raise ValueError(f"No step '{step_name}' in task '{task_name}'")
        step.fail(error)
        self._persist()

    def get_resume_point(self, task_name: str) -> Optional[str]:
        """Get the step name where execution should resume."""
        progress = self.tasks.get(task_name)
        if not progress:
            return None
        step = progress.resume_point()
        return step.name if step else None

    def _persist(self):
        if not self.persist_path:
            return
        data = {name: tp.to_dict() for name, tp in self.tasks.items()}
        Path(self.persist_path).write_text(json.dumps(data, indent=2))

    def load(self):
        """Load persisted progress."""
        if not self.persist_path:
            return
        path = Path(self.persist_path)
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for name, tp_data in data.items():
            self.tasks[name] = TaskProgress.from_dict(tp_data)

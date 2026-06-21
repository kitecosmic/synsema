"""
Synsema Native Cron — Scheduled task execution.

Schedule tasks to run at intervals or specific times:

    cron_every(30, sync_inventory)              -- every 30 seconds
    cron_every(3600, generate_report)           -- every hour
    cron_after(10, send_notification)           -- once, after 10 seconds
    cron_cancel("sync_inventory")               -- cancel a scheduled task
    cron_list()                                 -- show all scheduled tasks

Each scheduled task runs in its own thread. The cron scheduler
runs as a background daemon thread — it doesn't block the program.

Uses only Python stdlib (threading.Timer). No APScheduler, no celery.
"""

import threading
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field


@dataclass
class CronJob:
    """A scheduled job."""
    name: str
    interval_seconds: float
    task_fn: Callable
    repeating: bool = True
    active: bool = True
    run_count: int = 0
    last_run: float = 0
    created_at: float = 0
    timer: Optional[threading.Timer] = field(default=None, repr=False)
    errors: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()


class CronScheduler:
    """
    Background task scheduler for Synsema.

    Manages recurring and one-shot scheduled tasks.
    Each task runs in its own thread. The scheduler is non-blocking.
    """

    def __init__(self):
        self.jobs: Dict[str, CronJob] = {}
        self._lock = threading.Lock()

    def every(self, interval_seconds: float, name: str,
              task_fn: Callable) -> CronJob:
        """Schedule a repeating task."""
        with self._lock:
            # Cancel existing job with same name
            if name in self.jobs:
                self._cancel_job(self.jobs[name])

            job = CronJob(
                name=name,
                interval_seconds=interval_seconds,
                task_fn=task_fn,
                repeating=True,
            )
            self.jobs[name] = job
            self._schedule_next(job)
            return job

    def after(self, delay_seconds: float, name: str,
              task_fn: Callable) -> CronJob:
        """Schedule a one-shot task after a delay."""
        with self._lock:
            if name in self.jobs:
                self._cancel_job(self.jobs[name])

            job = CronJob(
                name=name,
                interval_seconds=delay_seconds,
                task_fn=task_fn,
                repeating=False,
            )
            self.jobs[name] = job
            self._schedule_next(job)
            return job

    def cancel(self, name: str) -> bool:
        """Cancel a scheduled job."""
        with self._lock:
            if name in self.jobs:
                self._cancel_job(self.jobs[name])
                del self.jobs[name]
                return True
            return False

    def cancel_all(self):
        """Cancel all jobs."""
        with self._lock:
            for job in self.jobs.values():
                self._cancel_job(job)
            self.jobs.clear()

    def list_jobs(self) -> List[Dict[str, Any]]:
        """List all active jobs."""
        with self._lock:
            result = []
            for job in self.jobs.values():
                result.append({
                    "name": job.name,
                    "interval": job.interval_seconds,
                    "repeating": job.repeating,
                    "active": job.active,
                    "run_count": job.run_count,
                    "last_run": job.last_run,
                    "errors": len(job.errors),
                })
            return result

    def _schedule_next(self, job: CronJob):
        """Schedule the next execution of a job."""
        if not job.active:
            return

        def run():
            job.last_run = time.time()
            job.run_count += 1
            try:
                job.task_fn()
            except Exception as e:
                job.errors.append(f"Run {job.run_count}: {e}")
            # Reschedule if repeating
            if job.repeating and job.active:
                self._schedule_next(job)

        timer = threading.Timer(job.interval_seconds, run)
        timer.daemon = True
        job.timer = timer
        timer.start()

    def _cancel_job(self, job: CronJob):
        job.active = False
        if job.timer:
            job.timer.cancel()

    def format_status(self) -> str:
        jobs = self.list_jobs()
        if not jobs:
            return "No scheduled tasks."
        lines = [f"Scheduled Tasks ({len(jobs)}):"]
        for j in jobs:
            repeat = f"every {j['interval']}s" if j['repeating'] else "once"
            status = "active" if j['active'] else "cancelled"
            lines.append(
                f"  [{status}] {j['name']}: {repeat}, "
                f"runs: {j['run_count']}, errors: {j['errors']}"
            )
        return "\n".join(lines)


def register_cron_builtins(env, scheduler: CronScheduler, interpreter=None,
                           live_output: bool = True):
    """Register cron builtins in a Synsema environment."""
    import sys as _sys
    from ..core.types import (
        SynValue, BuiltinTask, SynTask, SynTaskValue,
        syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
    )

    # For cron tasks, output goes directly to stdout (not buffered)
    _original_output = interpreter.output_callback if interpreter else None

    def _cron_output(text):
        """Route cron task output to stdout in real time."""
        if _original_output:
            _original_output(text)
        # Also print to real stdout for serve/daemon mode
        print(text, flush=True)

    def _cron_every(args):
        """cron_every(seconds, task_or_name)"""
        interval = float(args[0].raw)
        task_val = args[1]

        # Get task name and callable
        if isinstance(task_val.raw, SynTaskValue):
            name = task_val.raw.name
            def run():
                if interpreter:
                    saved_cb = interpreter.output_callback
                    interpreter.output_callback = _cron_output
                    try:
                        interpreter._call_value(task_val, [], None)
                    finally:
                        interpreter.output_callback = saved_cb
        elif isinstance(task_val.raw, BuiltinTask):
            name = task_val.raw.name
            def run():
                task_val.raw.func([])
        else:
            name = str(task_val.raw)
            def run():
                pass

        scheduler.every(interval, name, run)
        return syn_text(name)

    def _cron_after(args):
        """cron_after(seconds, task_or_name)"""
        delay = float(args[0].raw)
        task_val = args[1]

        if isinstance(task_val.raw, SynTaskValue):
            name = task_val.raw.name
            def run():
                if interpreter:
                    interpreter._call_value(task_val, [], None)
        elif isinstance(task_val.raw, BuiltinTask):
            name = task_val.raw.name
            def run():
                task_val.raw.func([])
        else:
            name = str(task_val.raw)
            def run():
                pass

        scheduler.after(delay, name, run)
        return syn_text(name)

    def _cron_cancel(args):
        """cron_cancel(name)"""
        name = str(args[0].raw)
        return syn_bool(scheduler.cancel(name))

    def _cron_list(args):
        """cron_list() → list of job info maps"""
        jobs = scheduler.list_jobs()
        result = []
        for j in jobs:
            result.append(syn_map({
                "name": syn_text(j["name"]),
                "interval": syn_number(j["interval"]),
                "repeating": syn_bool(j["repeating"]),
                "active": syn_bool(j["active"]),
                "run_count": syn_number(j["run_count"]),
            }))
        return syn_list(result)

    def _cron_status(args):
        """cron_status() → formatted text"""
        return syn_text(scheduler.format_status())

    builtins = {
        "cron_every": BuiltinTask("cron_every", _cron_every, 2),
        "cron_after": BuiltinTask("cron_after", _cron_after, 2),
        "cron_cancel": BuiltinTask("cron_cancel", _cron_cancel, 1),
        "cron_list": BuiltinTask("cron_list", _cron_list, 0),
        "cron_status": BuiltinTask("cron_status", _cron_status, 0),
    }
    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTask()))

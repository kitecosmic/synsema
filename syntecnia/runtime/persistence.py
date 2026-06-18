"""
Syntecnia State Persistence — Survive restarts.

Agent memory, progress, decisions, and blackboard state persist to
a SQLite database. When an agent restarts (daemon restart, crash recovery,
new run), it loads its previous state automatically.

Storage: ~/.syntecnia/state/<program_name>.db
Or configured via: --state-db /path/to/state.db

Tables:
    memory      — agent memory entries (preferences, learnings, etc.)
    rules       — owner rules
    progress    — task step progress
    decisions   — human decision log
    blackboard  — shared state snapshots
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

from ..agents.memory import AgentMemory, MemoryEntry, MemoryCategory, OwnerRule, RuleLevel
from ..agents.progress import ProgressManager, TaskProgress, TaskStep, StepStatus


def _default_state_path(program_name: str) -> str:
    d = Path.home() / ".syntecnia" / "state"
    d.mkdir(parents=True, exist_ok=True)
    return str(d / f"{program_name}.db")


class StatePersistence:
    """
    Persists agent state to SQLite between runs.

    Usage:
        persistence = StatePersistence("my_agent")
        persistence.load_into(agent_memory, progress_manager)
        # ... run program ...
        persistence.save_from(agent_memory, progress_manager)
    """

    def __init__(self, db_path: str = None, program_name: str = "default"):
        self.db_path = db_path or _default_state_path(program_name)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS memory (
                id TEXT PRIMARY KEY,
                category TEXT,
                content TEXT,
                data TEXT,
                tags TEXT,
                source TEXT,
                confidence REAL,
                active INTEGER,
                created_at REAL,
                updated_at REAL
            );
            CREATE TABLE IF NOT EXISTS rules (
                name TEXT PRIMARY KEY,
                level TEXT,
                description TEXT,
                condition TEXT,
                action TEXT,
                category TEXT,
                tags TEXT,
                active INTEGER
            );
            CREATE TABLE IF NOT EXISTS progress (
                task_name TEXT,
                step_name TEXT,
                status TEXT,
                started_at REAL,
                finished_at REAL,
                result TEXT,
                error TEXT,
                metadata TEXT,
                retries INTEGER,
                PRIMARY KEY (task_name, step_name)
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                error_type TEXT,
                error_message TEXT,
                context TEXT,
                options TEXT,
                chosen_option TEXT,
                chosen_label TEXT,
                outcome TEXT
            );
        """)
        self.conn.commit()

    def save_from(self, memory: AgentMemory, progress: ProgressManager):
        """Save current state to database."""
        self._save_memory(memory)
        self._save_rules(memory)
        self._save_progress(progress)

    def load_into(self, memory: AgentMemory, progress: ProgressManager):
        """Load persisted state into memory and progress managers."""
        self._load_memory(memory)
        self._load_rules(memory)
        self._load_progress(progress)

    def _save_memory(self, memory: AgentMemory):
        for entry_id, entry in memory.entries.items():
            self.conn.execute("""
                INSERT OR REPLACE INTO memory
                (id, category, content, data, tags, source, confidence, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.id, entry.category.value, entry.content,
                json.dumps(entry.data), json.dumps(entry.tags),
                entry.source, entry.confidence, int(entry.active),
                entry.created_at, entry.updated_at,
            ))
        self.conn.commit()

    def _load_memory(self, memory: AgentMemory):
        cursor = self.conn.execute("SELECT * FROM memory WHERE active = 1")
        max_counter = 0
        for row in cursor.fetchall():
            entry = MemoryEntry(
                id=row[0],
                category=MemoryCategory(row[1]),
                content=row[2],
                data=json.loads(row[3]) if row[3] else {},
                tags=json.loads(row[4]) if row[4] else [],
                source=row[5] or "",
                confidence=row[6] or 1.0,
                active=bool(row[7]),
                created_at=row[8] or 0,
                updated_at=row[9] or 0,
            )
            memory.entries[entry.id] = entry
            # Track counter
            if "_" in entry.id:
                try:
                    num = int(entry.id.split("_")[1])
                    max_counter = max(max_counter, num)
                except ValueError:
                    pass
        memory._counter = max(memory._counter, max_counter)

    def _save_rules(self, memory: AgentMemory):
        for name, rule in memory.rules.items():
            self.conn.execute("""
                INSERT OR REPLACE INTO rules
                (name, level, description, condition, action, category, tags, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.name, rule.level.value, rule.description,
                rule.condition, rule.action, rule.category,
                json.dumps(rule.tags), int(rule.active),
            ))
        self.conn.commit()

    def _load_rules(self, memory: AgentMemory):
        cursor = self.conn.execute("SELECT * FROM rules WHERE active = 1")
        for row in cursor.fetchall():
            rule = OwnerRule(
                name=row[0],
                level=RuleLevel(row[1]),
                description=row[2],
                condition=row[3],
                action=row[4] or "warn",
                category=row[5] or "",
                tags=json.loads(row[6]) if row[6] else [],
                active=bool(row[7]),
            )
            memory.rules[rule.name] = rule

    def _save_progress(self, progress: ProgressManager):
        for task_name, task_progress in progress.tasks.items():
            for step in task_progress.steps:
                self.conn.execute("""
                    INSERT OR REPLACE INTO progress
                    (task_name, step_name, status, started_at, finished_at,
                     result, error, metadata, retries)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    task_name, step.name, step.status.value,
                    step.started_at, step.finished_at,
                    step.result, step.error,
                    json.dumps(step.metadata), step.retries,
                ))
        self.conn.commit()

    def _load_progress(self, progress: ProgressManager):
        cursor = self.conn.execute(
            "SELECT DISTINCT task_name FROM progress"
        )
        for (task_name,) in cursor.fetchall():
            step_cursor = self.conn.execute(
                "SELECT * FROM progress WHERE task_name = ? ORDER BY rowid",
                (task_name,),
            )
            steps = []
            for row in step_cursor.fetchall():
                step = TaskStep(name=row[1])
                step.status = StepStatus(row[2])
                step.started_at = row[3]
                step.finished_at = row[4]
                step.result = row[5]
                step.error = row[6]
                step.metadata = json.loads(row[7]) if row[7] else {}
                step.retries = row[8] or 0
                steps.append(step)

            tp = TaskProgress(task_name=task_name)
            tp.steps = steps
            progress.tasks[task_name] = tp

    def save_decision(self, decision):
        """Save a human decision."""
        self.conn.execute("""
            INSERT INTO decisions
            (timestamp, error_type, error_message, context, options,
             chosen_option, chosen_label, outcome)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            decision.timestamp, decision.error_type,
            decision.error_message, decision.context,
            json.dumps(decision.options_presented),
            decision.chosen_option, decision.chosen_label,
            decision.outcome,
        ))
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

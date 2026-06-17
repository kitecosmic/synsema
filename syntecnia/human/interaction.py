"""
Syntecnia Human Interaction System.

Human interaction is a first-class concept in Syntecnia. Unlike traditional
programs where human interaction is an afterthought (print/input), Syntecnia
treats human checkpoints as structural elements of the program.

Interaction types:
    - approve: Binary yes/no decision point (gating)
    - confirm: Confirmation before irreversible action
    - ask: Request information or choice from human
    - show: Display data for human review (non-blocking)
    - review: Present a diff/change for human review

The interaction system supports multiple backends:
    - Terminal (stdin/stdout)
    - Web (HTTP endpoint for approval)
    - Callback (programmatic, for embedding)
    - Auto (for testing/CI — auto-approves everything)
    - Queue (async — queues requests, human responds later)
"""

import time
import threading
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum, auto


class InteractionType(Enum):
    APPROVE = auto()
    CONFIRM = auto()
    ASK = auto()
    SHOW = auto()
    REVIEW = auto()


class InteractionStatus(Enum):
    PENDING = auto()
    APPROVED = auto()
    DENIED = auto()
    ANSWERED = auto()
    TIMEOUT = auto()


@dataclass
class InteractionRequest:
    """A request for human interaction."""
    id: str
    type: InteractionType
    message: str
    context: Optional[Dict] = None
    options: Optional[List[str]] = None
    agent_name: str = ""
    created_at: float = 0.0
    timeout_seconds: Optional[float] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()


@dataclass
class InteractionResponse:
    """Human's response to an interaction request."""
    request_id: str
    status: InteractionStatus
    value: Any = None
    responded_at: float = 0.0

    def __post_init__(self):
        if not self.responded_at:
            self.responded_at = time.time()


class HumanHandler(ABC):
    """Base class for human interaction backends."""

    @abstractmethod
    def handle(self, request: InteractionRequest) -> InteractionResponse:
        pass


class TerminalHandler(HumanHandler):
    """Interactive terminal handler — prompts the user via stdin."""

    def handle(self, request: InteractionRequest) -> InteractionResponse:
        print()  # blank line for readability

        if request.type == InteractionType.SHOW:
            label = f"[{request.agent_name}] " if request.agent_name else ""
            print(f"{label}SHOW: {request.message}")
            if request.context:
                for k, v in request.context.items():
                    print(f"  {k}: {v}")
            return InteractionResponse(
                request_id=request.id,
                status=InteractionStatus.ANSWERED,
            )

        if request.type in (InteractionType.APPROVE, InteractionType.CONFIRM):
            action = "Approve" if request.type == InteractionType.APPROVE else "Confirm"
            print(f"[{action}] {request.message}")
            if request.context:
                for k, v in request.context.items():
                    print(f"  {k}: {v}")

            while True:
                answer = input(f"  {action}? (y/n): ").strip().lower()
                if answer in ("y", "yes"):
                    return InteractionResponse(
                        request_id=request.id,
                        status=InteractionStatus.APPROVED,
                        value=True,
                    )
                elif answer in ("n", "no"):
                    return InteractionResponse(
                        request_id=request.id,
                        status=InteractionStatus.DENIED,
                        value=False,
                    )
                print("  Please answer 'y' or 'n'")

        if request.type == InteractionType.ASK:
            print(f"[Question] {request.message}")
            if request.options:
                for i, opt in enumerate(request.options, 1):
                    print(f"  {i}. {opt}")
                while True:
                    answer = input("  Choice (number or text): ").strip()
                    if answer.isdigit():
                        idx = int(answer) - 1
                        if 0 <= idx < len(request.options):
                            return InteractionResponse(
                                request_id=request.id,
                                status=InteractionStatus.ANSWERED,
                                value=request.options[idx],
                            )
                    elif answer in request.options:
                        return InteractionResponse(
                            request_id=request.id,
                            status=InteractionStatus.ANSWERED,
                            value=answer,
                        )
                    print("  Invalid choice, try again")
            else:
                answer = input("  Answer: ").strip()
                return InteractionResponse(
                    request_id=request.id,
                    status=InteractionStatus.ANSWERED,
                    value=answer,
                )

        if request.type == InteractionType.REVIEW:
            print(f"[Review] {request.message}")
            if request.context:
                for k, v in request.context.items():
                    print(f"  {k}: {v}")
            while True:
                answer = input("  Accept? (y/n): ").strip().lower()
                if answer in ("y", "yes"):
                    return InteractionResponse(
                        request_id=request.id,
                        status=InteractionStatus.APPROVED,
                        value=True,
                    )
                elif answer in ("n", "no"):
                    return InteractionResponse(
                        request_id=request.id,
                        status=InteractionStatus.DENIED,
                        value=False,
                    )

        return InteractionResponse(
            request_id=request.id,
            status=InteractionStatus.ANSWERED,
        )


class AutoHandler(HumanHandler):
    """Auto-approves everything. For testing and CI."""

    def __init__(self, default_approve: bool = True, default_answer: str = ""):
        self.default_approve = default_approve
        self.default_answer = default_answer
        self.log: List[InteractionRequest] = []

    def handle(self, request: InteractionRequest) -> InteractionResponse:
        self.log.append(request)
        if request.type in (InteractionType.APPROVE, InteractionType.CONFIRM, InteractionType.REVIEW):
            return InteractionResponse(
                request_id=request.id,
                status=InteractionStatus.APPROVED if self.default_approve else InteractionStatus.DENIED,
                value=self.default_approve,
            )
        if request.type == InteractionType.ASK:
            value = self.default_answer
            if request.options:
                value = request.options[0]
            return InteractionResponse(
                request_id=request.id,
                status=InteractionStatus.ANSWERED,
                value=value,
            )
        return InteractionResponse(
            request_id=request.id,
            status=InteractionStatus.ANSWERED,
        )


class QueueHandler(HumanHandler):
    """
    Async queue handler — queues requests and waits for external responses.

    Useful for web-based UIs where a human responds asynchronously.
    The agent blocks on the request until the human responds.
    """

    def __init__(self):
        self.pending: Dict[str, InteractionRequest] = {}
        self.responses: Dict[str, InteractionResponse] = {}
        self._events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def handle(self, request: InteractionRequest) -> InteractionResponse:
        event = threading.Event()
        with self._lock:
            self.pending[request.id] = request
            self._events[request.id] = event

        # Block until human responds
        timeout = request.timeout_seconds or 300  # 5 minute default
        signaled = event.wait(timeout=timeout)

        with self._lock:
            self.pending.pop(request.id, None)
            self._events.pop(request.id, None)

        if not signaled:
            return InteractionResponse(
                request_id=request.id,
                status=InteractionStatus.TIMEOUT,
            )

        return self.responses.get(request.id, InteractionResponse(
            request_id=request.id,
            status=InteractionStatus.TIMEOUT,
        ))

    def respond(self, request_id: str, value: Any, approved: bool = True):
        """External call to respond to a pending request."""
        with self._lock:
            status = InteractionStatus.APPROVED if approved else InteractionStatus.DENIED
            self.responses[request_id] = InteractionResponse(
                request_id=request_id,
                status=status,
                value=value,
            )
            if request_id in self._events:
                self._events[request_id].set()

    def get_pending(self) -> List[InteractionRequest]:
        """Get all pending requests (for UI to display)."""
        with self._lock:
            return list(self.pending.values())


class InteractionManager:
    """
    Manages all human interaction for a Syntecnia program.

    Provides the callback interface that the interpreter uses,
    backed by a configurable handler.
    """

    def __init__(self, handler: HumanHandler = None):
        self.handler = handler or AutoHandler()
        self.history: List[tuple] = []  # (request, response) pairs
        self._counter = 0
        self._lock = threading.Lock()

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"interact_{self._counter}"

    def get_callback(self) -> Callable:
        """
        Get a callback function for the interpreter.

        Returns a function with signature:
            callback(action: str, message: str) -> Any
        """
        def callback(action: str, message: str) -> Any:
            type_map = {
                "approve": InteractionType.APPROVE,
                "confirm": InteractionType.CONFIRM,
                "ask": InteractionType.ASK,
                "show": InteractionType.SHOW,
                "review": InteractionType.REVIEW,
            }
            interaction_type = type_map.get(action, InteractionType.SHOW)

            request = InteractionRequest(
                id=self._next_id(),
                type=interaction_type,
                message=message,
            )

            response = self.handler.handle(request)
            self.history.append((request, response))

            if interaction_type in (InteractionType.APPROVE, InteractionType.CONFIRM, InteractionType.REVIEW):
                return response.status == InteractionStatus.APPROVED
            return response.value or ""

        return callback

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .models import TaskStatus, TERMINAL_STATUSES


class TaskPhase(StrEnum):
    dispatch = "dispatch"
    worker = "worker"
    validation = "validation"
    review = "review"
    integration = "integration"
    terminal = "terminal"
    recovery = "recovery"


@dataclass(frozen=True)
class TaskTransition:
    status: TaskStatus
    summary: str
    phase: TaskPhase


class InvalidTaskTransition(ValueError):
    def __init__(self, current: TaskStatus, transition: TaskTransition):
        super().__init__(
            f"invalid task transition {current.value} -> "
            f"{transition.status.value} ({transition.phase.value})"
        )
        self.current = current
        self.transition = transition


def worker_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.worker)


def validation_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.validation)


def review_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.reviewing, summary, TaskPhase.review)


def integration_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.integrating, summary, TaskPhase.integration)


def terminal_status(status: TaskStatus, summary: str) -> TaskTransition:
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"{status.value} is not terminal")
    return TaskTransition(status, summary, TaskPhase.terminal)


def recovery_failed(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.failed, summary, TaskPhase.recovery)


def transition_allowed(current: TaskStatus, transition: TaskTransition) -> bool:
    target = transition.status
    if current in TERMINAL_STATUSES:
        return current == target
    if target in TERMINAL_STATUSES:
        return current != TaskStatus.queued or transition.phase in {
            TaskPhase.dispatch,
            TaskPhase.terminal,
        }
    if current == TaskStatus.queued:
        return target in {TaskStatus.running, TaskStatus.integrating}
    if current == TaskStatus.running:
        return target in {
            TaskStatus.running,
            TaskStatus.reviewing,
            TaskStatus.integrating,
        }
    if current == TaskStatus.reviewing:
        return target in {TaskStatus.running, TaskStatus.reviewing}
    if current == TaskStatus.integrating:
        return target in {TaskStatus.running, TaskStatus.integrating}
    return False


def require_transition_allowed(
    current: TaskStatus, transition: TaskTransition
) -> None:
    if not transition_allowed(current, transition):
        raise InvalidTaskTransition(current, transition)

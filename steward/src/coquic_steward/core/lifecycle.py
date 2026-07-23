from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
import json
from typing import Any, Mapping

from .models import (
    PipelineCursorPhase,
    PipelinePhase,
    PipelineState,
    PipelineTrigger,
    TaskStatus,
    TERMINAL_STATUSES,
)


class TaskPhase(StrEnum):
    dispatch = "dispatch"
    implementation_plan = "implementation_plan"
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


@dataclass(frozen=True)
class PhaseInput:
    """Immutable input identity captured before a phase has side effects."""

    task_id: str
    pipeline_id: str
    action_id: str
    phase: PipelineCursorPhase | str
    base_identity: str | None = None
    input_identity: str | None = None
    patch_identity: str | None = None
    expected_tree: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "pipeline_id": self.pipeline_id,
            "action_id": self.action_id,
            "phase": str(self.phase),
            "base_identity": self.base_identity,
            "input_identity": self.input_identity,
            "patch_identity": self.patch_identity,
            "expected_tree": self.expected_tree,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class PhaseOutput:
    """Result identity captured after a phase action completes."""

    action_id: str
    phase: PipelineCursorPhase | str
    next_phase: PipelineCursorPhase | str | None
    state: PipelineState | str = PipelineState.active
    output_identity: str | None = None
    patch_identity: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "phase": str(self.phase),
            "next_phase": str(self.next_phase) if self.next_phase is not None else None,
            "state": str(self.state),
            "output_identity": self.output_identity,
            "patch_identity": self.patch_identity,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class AdvanceResult:
    """Outcome of one claimed durable pipeline action."""

    task_id: str
    pipeline_id: str
    phase: PipelineCursorPhase | str
    next_phase: PipelineCursorPhase | str | None
    status: str
    action_id: str | None = None
    progressed: bool = False
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PipelineTransition:
    current: PipelineCursorPhase | str
    target: PipelineCursorPhase | str
    trigger: PipelineTrigger | str = PipelineTrigger.initial


class InvalidPipelineTransition(ValueError):
    def __init__(self, transition: PipelineTransition):
        super().__init__(
            f"invalid pipeline transition {transition.current!s} -> "
            f"{transition.target!s} ({transition.trigger!s})"
        )
        self.transition = transition


_PIPELINE_TRANSITIONS: dict[PipelineCursorPhase, frozenset[PipelineCursorPhase]] = {
    PipelineCursorPhase.provisioned: frozenset(
        {PipelineCursorPhase.planning, PipelineCursorPhase.implementation}
    ),
    PipelineCursorPhase.planning: frozenset({PipelineCursorPhase.implementation}),
    PipelineCursorPhase.implementation: frozenset(
        {PipelineCursorPhase.validation, PipelineCursorPhase.ready_to_seal}
    ),
    PipelineCursorPhase.validation: frozenset(
        {PipelineCursorPhase.review, PipelineCursorPhase.repair}
    ),
    PipelineCursorPhase.review: frozenset(
        {PipelineCursorPhase.formality, PipelineCursorPhase.integration, PipelineCursorPhase.repair}
    ),
    PipelineCursorPhase.formality: frozenset(
        {PipelineCursorPhase.integration, PipelineCursorPhase.repair}
    ),
    PipelineCursorPhase.repair: frozenset({PipelineCursorPhase.implementation}),
    PipelineCursorPhase.integration: frozenset({PipelineCursorPhase.commit_message}),
    PipelineCursorPhase.commit_message: frozenset({PipelineCursorPhase.commit}),
    PipelineCursorPhase.commit: frozenset({PipelineCursorPhase.push, PipelineCursorPhase.ready_to_seal}),
    PipelineCursorPhase.push: frozenset({PipelineCursorPhase.ready_to_seal}),
    PipelineCursorPhase.ready_to_seal: frozenset(),
}


def pipeline_transition_allowed(
    current: PipelineCursorPhase | str,
    target: PipelineCursorPhase | str,
    *,
    trigger: PipelineTrigger | str = PipelineTrigger.initial,
) -> bool:
    try:
        source = PipelineCursorPhase(current)
        destination = PipelineCursorPhase(target)
        selected_trigger = PipelineTrigger(trigger)
    except ValueError:
        return False
    if source == destination:
        return True
    if source == PipelineCursorPhase.provisioned:
        return destination in _PIPELINE_TRANSITIONS[PipelineCursorPhase.provisioned]
    if selected_trigger == PipelineTrigger.validation_repair:
        return source == PipelineCursorPhase.validation and destination == PipelineCursorPhase.repair
    if selected_trigger == PipelineTrigger.review_repair:
        return source in {PipelineCursorPhase.review, PipelineCursorPhase.formality} and destination == PipelineCursorPhase.repair
    if selected_trigger in {
        PipelineTrigger.integration_rebase,
        PipelineTrigger.integration_conflict,
        PipelineTrigger.push_race,
    }:
        return destination == PipelineCursorPhase.implementation
    return destination in _PIPELINE_TRANSITIONS.get(source, frozenset())


def require_pipeline_transition(
    current: PipelineCursorPhase | str,
    target: PipelineCursorPhase | str,
    *,
    trigger: PipelineTrigger | str = PipelineTrigger.initial,
) -> None:
    transition = PipelineTransition(current, target, trigger)
    if not pipeline_transition_allowed(current, target, trigger=trigger):
        raise InvalidPipelineTransition(transition)


def coarse_phase(phase: PipelineCursorPhase | str) -> PipelinePhase:
    """Map a fine cursor to the compatibility phase persisted by Plan 002."""

    selected = PipelineCursorPhase(phase)
    if selected in {PipelineCursorPhase.provisioned, PipelineCursorPhase.planning}:
        return PipelinePhase.planning
    if selected in {PipelineCursorPhase.implementation, PipelineCursorPhase.repair}:
        return PipelinePhase.implementation
    if selected == PipelineCursorPhase.validation:
        return PipelinePhase.validation
    if selected in {PipelineCursorPhase.review, PipelineCursorPhase.formality}:
        return PipelinePhase.review
    if selected in {
        PipelineCursorPhase.integration,
        PipelineCursorPhase.commit_message,
        PipelineCursorPhase.commit,
        PipelineCursorPhase.push,
    }:
        return PipelinePhase.integration
    return PipelinePhase.complete


def action_identity(task_id: str, pipeline_id: str, phase: PipelineCursorPhase | str) -> str:
    try:
        selected = PipelineCursorPhase(phase).value
    except ValueError:
        selected = str(phase)
    return f"{task_id}:{pipeline_id}:{selected}"


def bounded_fingerprint(*values: Any, limit: int = 128) -> str:
    """Return a stable, bounded fingerprint suitable for no-progress guards."""

    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8", errors="replace")).hexdigest()[:limit]


def worker_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.worker)


def implementation_plan_started(summary: str) -> TaskTransition:
    return TaskTransition(TaskStatus.running, summary, TaskPhase.implementation_plan)


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
        return target in {TaskStatus.running, TaskStatus.reviewing, TaskStatus.integrating}
    if current == TaskStatus.integrating:
        return target in {TaskStatus.running, TaskStatus.integrating}
    return False


def require_transition_allowed(
    current: TaskStatus, transition: TaskTransition
) -> None:
    if not transition_allowed(current, transition):
        raise InvalidTaskTransition(current, transition)

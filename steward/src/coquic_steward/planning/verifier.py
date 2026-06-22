from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from ..core.models import (
    Priority,
    ProjectSignals,
    Risk,
    SignalItem,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
)

PLANNABLE_WORKERS = {
    WorkerKind.interop_doctor,
    WorkerKind.code_quality_janitor,
    WorkerKind.ci_doctor,
    WorkerKind.rfc_auditor,
    WorkerKind.issue_implementer,
    WorkerKind.work_item_creator,
    WorkerKind.custom,
}


class ActiveTaskSummary(BaseModel):
    id: str
    kind: str
    worker: str
    title: str
    status: str
    dedupe_key: str | None = None


class ProposedTask(BaseModel):
    dedupe_key: str
    kind: TaskKind
    worker: WorkerKind
    title: str
    prompt: str
    priority: Priority = Priority.medium
    risk: Risk = Risk.medium
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerifiedPlan(BaseModel):
    planned: list[tuple[TaskSpec, str]] = Field(default_factory=list)
    consumed_item_ids: list[str] = Field(default_factory=list)


class PlanVerifier:
    def __init__(self, *, max_tasks: int = 8):
        self.max_tasks = max_tasks

    def verify(
        self,
        raw_json: str,
        signals: ProjectSignals,
        active_tasks: list[ActiveTaskSummary],
    ) -> list[tuple[TaskSpec, str]]:
        return self.verify_plan(raw_json, signals, active_tasks).planned

    def verify_plan(
        self,
        raw_json: str,
        signals: ProjectSignals,
        active_tasks: list[ActiveTaskSummary],
    ) -> VerifiedPlan:
        try:
            decoded = json.loads(raw_json)
        except json.JSONDecodeError:
            return VerifiedPlan()
        consumed = _consumed_item_ids(decoded, signals)
        proposals = decoded.get("tasks") if isinstance(decoded, dict) else None
        if not isinstance(proposals, list):
            return VerifiedPlan(consumed_item_ids=consumed)

        accepted: list[tuple[TaskSpec, str]] = []
        seen: set[str] = set()
        rejected = False
        active_dedupes = {
            task.dedupe_key for task in active_tasks if task.dedupe_key is not None
        }
        active_kinds = {task.kind for task in active_tasks}
        evidence_ids = _evidence_ids(signals)
        for item in proposals:
            if len(accepted) >= self.max_tasks:
                break
            proposed = _verified_proposal(
                item,
                seen=seen,
                active_dedupes=active_dedupes,
                active_kinds=active_kinds,
                evidence_ids=evidence_ids,
            )
            if proposed is None:
                rejected = True
                continue
            accepted.append(
                (
                    _task_spec_from_proposal(proposed, signals.items),
                    proposed.dedupe_key,
                )
            )
            seen.add(proposed.dedupe_key)
        return VerifiedPlan(
            planned=accepted,
            consumed_item_ids=[] if rejected else consumed,
        )


def summarize_active_tasks(tasks) -> list[ActiveTaskSummary]:
    summaries: list[ActiveTaskSummary] = []
    for task in tasks:
        if TaskStatus(task.status) not in {
            TaskStatus.queued,
            TaskStatus.running,
            TaskStatus.reviewing,
            TaskStatus.integrating,
        }:
            continue
        metadata = getattr(task.spec, "metadata", {}) or {}
        dedupe_key = metadata.get("dedupe_key")
        summaries.append(
            ActiveTaskSummary(
                id=task.id,
                kind=str(task.spec.kind),
                worker=str(task.spec.worker),
                title=task.spec.title,
                status=str(task.status),
                dedupe_key=str(dedupe_key) if dedupe_key else None,
            )
        )
    return summaries


def _evidence_ids(signals: ProjectSignals) -> set[str]:
    ids = {"project"}
    for item in signals.items:
        ids.add(item.id)
    return ids


def _consumed_item_ids(
    decoded: object, signals: ProjectSignals
) -> list[str]:
    if not isinstance(decoded, dict):
        return []
    values = decoded.get("consumed_item_ids")
    if not isinstance(values, list):
        return []
    allowed = {item.id for item in signals.items}
    consumed: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str) or value not in allowed or value in seen:
            continue
        consumed.append(value)
        seen.add(value)
    return consumed


def _valid_text(value: str, max_length: int) -> bool:
    stripped = value.strip()
    return bool(stripped) and len(stripped) <= max_length


def _verified_proposal(
    item: object,
    *,
    seen: set[str],
    active_dedupes: set[str],
    active_kinds: set[str],
    evidence_ids: set[str],
) -> ProposedTask | None:
    try:
        proposed = ProposedTask.model_validate(item)
    except ValidationError:
        return None
    if not _proposal_is_acceptable(
        proposed,
        seen=seen,
        active_dedupes=active_dedupes,
        active_kinds=active_kinds,
        evidence_ids=evidence_ids,
    ):
        return None
    return proposed


def _proposal_is_acceptable(
    proposed: ProposedTask,
    *,
    seen: set[str],
    active_dedupes: set[str],
    active_kinds: set[str],
    evidence_ids: set[str],
) -> bool:
    return not any(
        (
            proposed.worker not in PLANNABLE_WORKERS,
            not _valid_text(proposed.dedupe_key, 160),
            proposed.dedupe_key in seen,
            proposed.dedupe_key in active_dedupes,
            proposed.kind.value in active_kinds,
            not _valid_text(proposed.title, 200),
            not _valid_text(proposed.prompt, 10_000),
            not proposed.evidence,
            any(evidence not in evidence_ids for evidence in proposed.evidence),
            not _metadata_is_bounded(proposed.metadata),
        )
    )


def _task_spec_from_proposal(
    proposed: ProposedTask, items: list[SignalItem]
) -> TaskSpec:
    metadata = dict(proposed.metadata)
    metadata["dedupe_key"] = proposed.dedupe_key
    metadata["evidence"] = list(proposed.evidence)
    source_context = _source_context(items, proposed)
    if source_context:
        metadata["source_context"] = source_context
    return TaskSpec(
        kind=proposed.kind,
        worker=proposed.worker,
        title=proposed.title.strip(),
        prompt=proposed.prompt.strip(),
        priority=proposed.priority,
        risk=proposed.risk,
        source="planner",
        metadata=metadata,
    )


def _metadata_is_bounded(metadata: dict[str, Any]) -> bool:
    try:
        encoded = json.dumps(metadata)
    except (TypeError, ValueError):
        return False
    return len(encoded) <= 4096


def _source_context(items: list[SignalItem], proposed: ProposedTask) -> dict[str, Any]:
    selected_items = _selected_signal_items(proposed, items)
    if not selected_items:
        return {}
    return {
        "selected_signal_item_ids": [item["id"] for item in selected_items],
        "selected_signal_items": selected_items,
    }


def _selected_signal_items(
    proposed: ProposedTask, items: list[SignalItem]
) -> list[dict[str, Any]]:
    selected = proposed.metadata.get("selected_signal_item_ids")
    candidates = selected if isinstance(selected, list) and selected else proposed.evidence
    selected_ids = {item for item in candidates if isinstance(item, str)}
    matched = [
        item.model_dump(mode="json")
        for item in items
        if item.id in selected_ids
    ]
    return matched[:8]

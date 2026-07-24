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
    TaskWorkflow,
    WorkerKind,
)

PLANNABLE_WORKERS = {
    WorkerKind.interop_doctor,
    WorkerKind.code_quality_janitor,
    WorkerKind.ci_doctor,
    WorkerKind.rfc_auditor,
    WorkerKind.feature_implementer,
    WorkerKind.issue_implementer,
    WorkerKind.work_item_creator,
    WorkerKind.custom,
}


class ActiveTaskSummary(BaseModel):
    id: str
    kind: str
    workflow: TaskWorkflow = TaskWorkflow.fix
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


class ProposalDisposition(BaseModel):
    """One ordinal planner output, including proposals that were rejected."""

    ordinal: int = Field(ge=1)
    outcome: str
    reason_code: str
    signal_ids: list[str] = Field(default_factory=list)
    dedupe_key: str | None = None
    task_id: str | None = None
    proposal: dict[str, Any] = Field(default_factory=dict)


class VerifiedPlan(BaseModel):
    planned: list[tuple[TaskSpec, str]] = Field(default_factory=list)
    consumed_item_ids: list[str] = Field(default_factory=list)
    dispositions: list[ProposalDisposition] = Field(default_factory=list)
    invalid_output: bool = False
    diagnostics: dict[str, Any] = Field(default_factory=dict)


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
        *,
        capacity: int | None = None,
    ) -> VerifiedPlan:
        try:
            decoded = json.loads(raw_json)
        except json.JSONDecodeError:
            return VerifiedPlan(
                invalid_output=True,
                diagnostics={"reason_code": "invalid_output", "message": "planner output is not JSON"},
            )
        consumed = _consumed_item_ids(decoded, signals)
        proposals = decoded.get("tasks") if isinstance(decoded, dict) else None
        if not isinstance(proposals, list):
            return VerifiedPlan(
                invalid_output=True,
                diagnostics={"reason_code": "invalid_output", "message": "planner output has no task list"},
            )

        accepted: list[tuple[TaskSpec, str]] = []
        dispositions: list[ProposalDisposition] = []
        seen: set[str] = set()
        active_dedupes = {
            task.dedupe_key for task in active_tasks if task.dedupe_key is not None
        }
        active_tasks_by_dedupe = {
            task.dedupe_key: task.id
            for task in active_tasks
            if task.dedupe_key is not None
        }
        active_kinds = {task.kind for task in active_tasks}
        evidence_ids = _evidence_ids(signals)
        limit = self.max_tasks if capacity is None else max(0, min(self.max_tasks, capacity))
        for ordinal, item in enumerate(proposals, 1):
            proposed, reason = _verified_proposal_with_reason(
                item,
                seen=seen,
                active_dedupes=active_dedupes,
                active_kinds=active_kinds,
                evidence_ids=evidence_ids,
                signals=signals,
            )
            evidence = _proposal_signal_ids(item, signals)
            if proposed is None:
                outcome = "policy_rejected" if reason.startswith("policy_") else "invalid"
                if reason in {"duplicate_dedupe", "active_dedupe"}:
                    outcome = "duplicate"
                dispositions.append(
                    ProposalDisposition(
                        ordinal=ordinal,
                        outcome=outcome,
                        reason_code=reason,
                        signal_ids=evidence,
                        dedupe_key=_proposal_dedupe(item),
                        task_id=(
                            active_tasks_by_dedupe.get(_proposal_dedupe(item))
                            if reason == "active_dedupe"
                            else None
                        ),
                        proposal=item if isinstance(item, dict) else {},
                    )
                )
                continue
            if len(accepted) >= limit:
                dispositions.append(
                    ProposalDisposition(
                        ordinal=ordinal,
                        outcome="capacity_skipped",
                        reason_code="capacity_exhausted",
                        signal_ids=evidence,
                        dedupe_key=proposed.dedupe_key,
                        proposal=proposed.model_dump(mode="json"),
                    )
                )
                continue
            task_spec = _task_spec_from_proposal(proposed, signals.items)
            accepted.append(
                (
                    task_spec,
                    proposed.dedupe_key,
                )
            )
            seen.add(proposed.dedupe_key)
            dispositions.append(
                ProposalDisposition(
                    ordinal=ordinal,
                    outcome="accepted",
                    reason_code="accepted",
                    signal_ids=evidence,
                    dedupe_key=proposed.dedupe_key,
                    proposal=proposed.model_dump(mode="json"),
                )
            )
        non_consuming = {"invalid", "policy_rejected", "capacity_skipped", "duplicate"}
        can_consume = not any(item.outcome in non_consuming for item in dispositions)
        return VerifiedPlan(
            planned=accepted,
            consumed_item_ids=consumed if can_consume else [],
            dispositions=dispositions,
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
                workflow=task.spec.workflow,
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


def _proposal_dedupe(item: object) -> str | None:
    if isinstance(item, dict) and isinstance(item.get("dedupe_key"), str):
        return item["dedupe_key"]
    return None


def _proposal_signal_ids(item: object, signals: ProjectSignals) -> list[str]:
    if not isinstance(item, dict):
        return []
    candidates = item.get("evidence")
    if not isinstance(candidates, list):
        candidates = []
    allowed = {signal.id for signal in signals.items}
    return [value for value in candidates if isinstance(value, str) and value in allowed]


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
    signals: ProjectSignals,
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
        signals=signals,
    ):
        return None
    return proposed


def _verified_proposal_with_reason(
    item: object,
    *,
    seen: set[str],
    active_dedupes: set[str],
    active_kinds: set[str],
    evidence_ids: set[str],
    signals: ProjectSignals,
) -> tuple[ProposedTask | None, str]:
    try:
        proposed = ProposedTask.model_validate(item)
    except ValidationError:
        return None, "invalid_shape"
    if not _valid_text(proposed.dedupe_key, 160):
        return None, "invalid_dedupe_key"
    if proposed.dedupe_key in seen:
        return None, "duplicate_dedupe"
    if proposed.dedupe_key in active_dedupes:
        return None, "active_dedupe"
    if proposed.kind.value in active_kinds:
        return None, "policy_active_kind"
    if not _valid_text(proposed.title, 200):
        return None, "invalid_title"
    if not _valid_text(proposed.prompt, 10_000):
        return None, "invalid_prompt"
    if not proposed.evidence:
        return None, "invalid_missing_evidence"
    if any(evidence not in evidence_ids for evidence in proposed.evidence):
        return None, "invalid_evidence_id"
    if not _metadata_is_bounded(proposed.metadata):
        return None, "policy_metadata_too_large"
    if not _feature_issue_proposal_is_safe(proposed, signals):
        return None, "policy_feature_issue_scope"
    if proposed.worker not in PLANNABLE_WORKERS:
        return None, "policy_worker"
    return proposed, "accepted"


def _proposal_is_acceptable(
    proposed: ProposedTask,
    *,
    seen: set[str],
    active_dedupes: set[str],
    active_kinds: set[str],
    evidence_ids: set[str],
    signals: ProjectSignals,
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
            not _feature_issue_proposal_is_safe(proposed, signals),
        )
    )


def _feature_issue_proposal_is_safe(
    proposed: ProposedTask, signals: ProjectSignals
) -> bool:
    selected = _selected_signal_items(proposed, signals.items)
    evidence = _signal_items_by_id(proposed.evidence, signals.items)
    feature_items = [
        item for item in [*selected, *evidence]
        if item.get("kind") == "github-issues.feature-request"
    ]
    if not feature_items:
        return True
    selected_feature_items = [
        item for item in selected if item.get("kind") == "github-issues.feature-request"
    ]
    feature_ids = {
        str(item.get("id"))
        for item in feature_items
        if isinstance(item.get("id"), str)
    }
    selected_ids = _item_ids(selected)
    evidence_ids = _item_ids(evidence)
    return (
        proposed.kind == TaskKind.feature
        and proposed.worker == WorkerKind.feature_implementer
        and len(selected) == 1
        and len(evidence) == 1
        and len(selected_feature_items) == 1
        and len(feature_ids) == 1
        and selected_ids == evidence_ids == feature_ids
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


def _signal_items_by_id(ids: list[str], items: list[SignalItem]) -> list[dict[str, Any]]:
    selected_ids = {item for item in ids if isinstance(item, str)}
    return [item.model_dump(mode="json") for item in items if item.id in selected_ids]


def _item_ids(items: list[dict[str, Any]]) -> set[str]:
    return {
        str(item.get("id"))
        for item in items
        if isinstance(item.get("id"), str)
    }

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from ..core.models import (
    Priority,
    ProjectSignals,
    Risk,
    SignalMessage,
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
                    _task_spec_from_proposal(proposed, signals.inbox_messages),
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
    for message in signals.inbox_messages:
        ids.add(message.id)
        if message.evidence_id:
            ids.add(message.evidence_id)
    for item in signals.inbox_items:
        ids.add(item.id)
        if item.evidence_id:
            ids.add(item.evidence_id)
    if signals.failed_interop_run_id:
        ids.add(f"interop:{signals.failed_interop_run_id}")
    if signals.failed_workflow_run_id:
        ids.add(f"workflow:{signals.failed_workflow_run_id}")
    if signals.has_codeql_findings:
        ids.add("codeql:open")
    if signals.has_codacy_findings:
        ids.add("codacy:open")
    return ids


def _consumed_item_ids(
    decoded: object, signals: ProjectSignals
) -> list[str]:
    if not isinstance(decoded, dict):
        return []
    values = decoded.get("consumed_item_ids")
    if not isinstance(values, list):
        return []
    allowed = {item.id for item in signals.inbox_items}
    if not allowed:
        allowed = {message.id for message in signals.inbox_messages}
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
    proposed: ProposedTask, inbox_messages: list[SignalMessage]
) -> TaskSpec:
    metadata = dict(proposed.metadata)
    metadata["dedupe_key"] = proposed.dedupe_key
    metadata["evidence"] = list(proposed.evidence)
    source_context = _source_context(inbox_messages, proposed)
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


def _source_context(
    inbox_messages: list[SignalMessage], proposed: ProposedTask
) -> dict[str, Any]:
    messages_by_id = {message.id: message for message in inbox_messages}
    source_ids = _source_message_ids(proposed, messages_by_id)
    messages = [messages_by_id[item] for item in source_ids if item in messages_by_id]
    selected_items = _selected_work_items(proposed, messages)
    if not messages and not selected_items:
        return {}
    return {
        "source_message_ids": [message.id for message in messages],
        "messages": [
            {
                "id": message.id,
                "provider": message.provider,
                "kind": message.kind,
                "title": message.title,
                "summary": message.summary,
                "evidence_id": message.evidence_id,
                "work_items": _message_work_items(message),
            }
            for message in messages
        ],
        "selected_work_items": selected_items,
    }


def _source_message_ids(
    proposed: ProposedTask, messages_by_id: dict[str, SignalMessage]
) -> list[str]:
    metadata_ids = proposed.metadata.get("source_message_ids")
    candidates = metadata_ids if isinstance(metadata_ids, list) else proposed.evidence
    result: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if not isinstance(item, str) or item not in messages_by_id or item in seen:
            continue
        result.append(item)
        seen.add(item)
    return result


def _selected_work_items(
    proposed: ProposedTask, messages: list[SignalMessage]
) -> list[dict[str, Any]]:
    available = _available_work_items(messages)
    if not available:
        return []
    selected = proposed.metadata.get("selected_work_item_ids")
    if not isinstance(selected, list) or not selected:
        return available[:3]
    selected_ids = {item for item in selected if isinstance(item, str)}
    matched = [
        item
        for item in available
        if isinstance(item.get("id"), str) and item["id"] in selected_ids
    ]
    return matched[:8] if matched else available[:3]


def _available_work_items(messages: list[SignalMessage]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for message in messages:
        items.extend(_message_work_items(message))
    return items


def _message_work_items(message: SignalMessage) -> list[dict[str, Any]]:
    values = message.payload.get("work_items")
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]

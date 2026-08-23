from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError

from ..agents.catalog import (
    AGENTS,
    PLANNER_DISPATCH_POLICY,
    REMOTE_WRITE_AUTHORITY,
    CanonicalRemoteWrite,
    RemoteWriteAuthorityKey,
    RemoteWriteIdentity,
)
from ..core.models import EffectActionKind, EffectProposal
from ..core.models import (
    EFFECT_RESULT_METADATA_KEY,
    EXECUTION_MODE_METADATA_KEY,
    LEGACY_EFFECT_RESULT_METADATA_KEY,
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


_RESERVED_ALLOCATION_METADATA_KEYS = frozenset(
    {
        EXECUTION_MODE_METADATA_KEY,
        EFFECT_RESULT_METADATA_KEY,
        LEGACY_EFFECT_RESULT_METADATA_KEY,
    }
)


@dataclass(frozen=True)
class _VerifiedProposal:
    proposed: ProposedTask
    canonical_remote_write: CanonicalRemoteWrite | None = None


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


def selected_signal_item_ids(
    metadata: dict[str, Any], consumed_item_ids: list[str]
) -> list[str]:
    selected = metadata.get("selected_signal_item_ids")
    candidates = selected if isinstance(selected, list) else consumed_item_ids
    allowed = set(consumed_item_ids)
    result: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        if not isinstance(value, str) or value in seen:
            continue
        if allowed and value not in allowed:
            continue
        result.append(value)
        seen.add(value)
    return result


class PlanVerifier:
    def __init__(self, *, max_tasks: int = 8):
        self.max_tasks = max_tasks

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
            proposed_task = proposed.proposed
            if len(accepted) >= limit:
                dispositions.append(
                    ProposalDisposition(
                        ordinal=ordinal,
                        outcome="capacity_skipped",
                        reason_code="capacity_exhausted",
                        signal_ids=evidence,
                        dedupe_key=proposed_task.dedupe_key,
                        proposal=proposed_task.model_dump(mode="json"),
                    )
                )
                continue
            task_spec = _task_spec_from_proposal(
                proposed_task,
                signals,
                canonical_remote_write=proposed.canonical_remote_write,
            )
            accepted.append(
                (
                    task_spec,
                    proposed_task.dedupe_key,
                )
            )
            seen.add(proposed_task.dedupe_key)
            dispositions.append(
                ProposalDisposition(
                    ordinal=ordinal,
                    outcome="accepted",
                    reason_code="accepted",
                    signal_ids=evidence,
                    dedupe_key=proposed_task.dedupe_key,
                    proposal=proposed_task.model_dump(mode="json"),
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


def _remote_write_identity_for_proposal(
    proposed: ProposedTask, signals: ProjectSignals
) -> tuple[RemoteWriteAuthorityKey, RemoteWriteIdentity] | None:
    if "selected_signal_item_ids" in proposed.metadata:
        selected_ids = proposed.metadata.get("selected_signal_item_ids")
        if not isinstance(selected_ids, list) or not selected_ids:
            return None
    else:
        selected_ids = list(proposed.evidence)
    if (
        len(selected_ids) != 1
        or len(proposed.evidence) != 1
        or selected_ids != proposed.evidence
        or not isinstance(selected_ids[0], str)
    ):
        return None
    matches = [item for item in signals.items if item.id == selected_ids[0]]
    if len(matches) != 1:
        return None
    item = matches[0]
    values = (item.id, item.provider, item.kind, signals.repository)
    if any(not value or value != value.strip() for value in values):
        return None
    key = RemoteWriteAuthorityKey(
        provider=item.provider,
        kind=item.kind,
        worker=proposed.worker,
    )
    return key, RemoteWriteIdentity(
        provider=item.provider,
        kind=item.kind,
        worker=proposed.worker,
        source_id=item.id,
        repository=signals.repository,
    )


def _canonical_remote_write_for_proposal(
    proposed: ProposedTask, signals: ProjectSignals
) -> CanonicalRemoteWrite | None:
    identity_pair = _remote_write_identity_for_proposal(proposed, signals)
    if identity_pair is None:
        return None
    key, identity = identity_pair
    authority = REMOTE_WRITE_AUTHORITY.get(key)
    if authority is None or not authority.canonicalizer_name.strip():
        return None
    try:
        operation = authority.canonicalizer(identity)
    except Exception:
        return None
    if not isinstance(operation, CanonicalRemoteWrite):
        return None
    if not _valid_text(operation.title, 200) or not _valid_text(
        operation.prompt, 10_000
    ):
        return None
    return operation


def _verified_proposal_with_reason(
    item: object,
    *,
    seen: set[str],
    active_dedupes: set[str],
    active_kinds: set[str],
    evidence_ids: set[str],
    signals: ProjectSignals,
) -> tuple[_VerifiedProposal | None, str]:
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
    if any(key in proposed.metadata for key in _RESERVED_ALLOCATION_METADATA_KEYS):
        return None, "policy_reserved_metadata"
    policy_kind = proposed.kind in PLANNER_DISPATCH_POLICY.kinds
    policy_worker = proposed.worker in PLANNER_DISPATCH_POLICY.workers
    policy_priority = proposed.priority in PLANNER_DISPATCH_POLICY.priorities
    policy_risk = proposed.risk in PLANNER_DISPATCH_POLICY.risks
    if not policy_kind:
        return None, "policy_kind"
    if not policy_worker:
        return None, "policy_worker"
    if not policy_priority:
        return None, "policy_priority"
    if not policy_risk:
        return None, "policy_risk"
    agent = AGENTS.get(proposed.worker)
    canonical_remote_write = None
    if agent is None:
        return None, "policy_worker"
    if agent.remote_writes:
        canonical_remote_write = _canonical_remote_write_for_proposal(
            proposed, signals
        )
        if canonical_remote_write is None:
            return None, "policy_remote_write_authority"
    if not _feature_issue_proposal_is_safe(proposed, signals):
        return None, "policy_feature_issue_scope"
    return _VerifiedProposal(proposed, canonical_remote_write), "accepted"


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
        and _feature_issue_identity(selected_feature_items[0], signals.repository)
        is not None
    )


def _task_spec_from_proposal(
    proposed: ProposedTask,
    signals: ProjectSignals,
    *,
    canonical_remote_write: CanonicalRemoteWrite | None = None,
) -> TaskSpec:
    metadata = dict(proposed.metadata)
    metadata["dedupe_key"] = proposed.dedupe_key
    metadata["evidence"] = list(proposed.evidence)
    source_context = _source_context(signals.items, proposed)
    if source_context:
        metadata["source_context"] = source_context
    title = proposed.title.strip()
    prompt = proposed.prompt.strip()
    if canonical_remote_write is not None:
        title = canonical_remote_write.title.strip()
        prompt = canonical_remote_write.prompt.strip()
        identity_pair = _remote_write_identity_for_proposal(proposed, signals)
        if identity_pair is not None:
            _key, identity = identity_pair
            proposal = EffectProposal(
                action=EffectActionKind.remote_write,
                action_id=f"remote-write:{identity.source_id}:{identity.worker.value}",
                target=identity.repository,
                payload={
                    "provider": identity.provider,
                    "kind": identity.kind,
                    "source_id": identity.source_id,
                    "worker": identity.worker.value,
                },
                reason="remote worker output requires a validated local proposal",
            )
            metadata["effect_proposal"] = proposal.as_dict()
    elif proposed.kind == TaskKind.feature:
        selected = _selected_signal_items(proposed, signals.items)
        identity = (
            _feature_issue_identity(selected[0], signals.repository)
            if len(selected) == 1
            and selected[0].get("kind") == "github-issues.feature-request"
            else None
        )
        if identity is not None:
            title, prompt = _canonical_feature_task(identity)
    return TaskSpec(
        kind=proposed.kind,
        worker=proposed.worker,
        title=title,
        prompt=prompt,
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


def _feature_issue_identity(
    item: dict[str, Any], repository: str
) -> tuple[int, str] | None:
    """Return a canonical issue identity only when the selected evidence agrees."""

    payload = item.get("payload")
    if not isinstance(payload, dict):
        return None
    raw_number = payload.get("issue_number")
    if isinstance(raw_number, bool):
        return None
    if isinstance(raw_number, int):
        number = raw_number
    elif isinstance(raw_number, str) and raw_number.isascii() and raw_number.isdigit():
        try:
            number = int(raw_number)
        except ValueError:
            return None
    else:
        return None
    if number < 1:
        return None

    repository = repository.strip()
    owner, separator, name = repository.partition("/")
    if (
        not separator
        or not owner
        or not name
        or "/" in name
        or any(character.isspace() for character in repository)
    ):
        return None
    raw_url = payload.get("issue_url")
    if not isinstance(raw_url, str) or not raw_url or raw_url != raw_url.strip():
        return None
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return None
    expected_path = f"/{repository}/issues/{number}"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
    ):
        return None
    return number, f"https://github.com/{repository}/issues/{number}"


def _canonical_feature_task(identity: tuple[int, str]) -> tuple[str, str]:
    number, url = identity
    return (
        f"Implement GitHub feature issue #{number}",
        f"Implement GitHub issue #{number} ({url}) as a local patch. "
        "Keep the change focused on the selected issue and add focused tests or "
        "validation. Do not comment on, label, close, or otherwise mutate GitHub "
        "issues, and do not commit or push.",
    )


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

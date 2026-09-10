from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from coquic_steward.execution.task_archive import (
    ArchiveInvocation,
    ArchiveConflictError,
    ArchiveImmutableError,
    ArchiveSealError,
    ArchiveValidationError,
    TaskArchive,
    MAX_ARCHIVE_INVOCATIONS,
)
from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import (
    EffectActionKind,
    EffectDecisionKind,
    EffectEvidence,
    EffectResult,
    ExecutionMode,
    TaskKind,
    TaskSpec,
    WorkerKind,
)
from coquic_steward.storage import TaskStore


COMPLETED_AT = "2026-07-22T00:00:04Z"


def _telemetry(
    task_id: str,
    invocation_id: str,
    retry_ordinal: int,
    *,
    completeness: str = "complete",
    process_outcome: str = "completed",
) -> dict[str, object]:
    turns = (
        [
            {
                "ordinal": 1,
                "input_tokens": 2,
                "cached_input_tokens": 1,
                "uncached_input_tokens": 1,
                "output_tokens": 1,
                "reasoning_output_tokens": 0,
                "total_tokens": 3,
            }
        ]
        if completeness == "complete"
        else []
    )
    return {
        "schema_version": 1,
        "provenance": "codex_exec_jsonl",
        "invocation_id": invocation_id,
        "task_id": task_id,
        "run_name": "worker",
        "stage": "code",
        "retry_ordinal": retry_ordinal,
        "configured_model": "model",
        "reasoning_effort": "low",
        "billing_mode": "unknown",
        "started_at": "2026-07-22T00:00:00.000Z",
        "completed_at": "2026-07-22T00:00:00.001Z",
        "duration_ms": 1,
        "first_agent_message_completed_ms": None,
        "process_outcome": process_outcome,
        "turns": turns,
        "aggregate": {
            "completed_turns": len(turns),
            "input_tokens": 2 if turns else 0,
            "cached_input_tokens": 1 if turns else 0,
            "uncached_input_tokens": 1 if turns else 0,
            "output_tokens": 1 if turns else 0,
            "reasoning_output_tokens": 0,
            "total_tokens": 3 if turns else 0,
        },
        "cost": {"status": "unavailable", "reason": "billing_mode_unknown"},
        "completeness": completeness,
        "issues": [],
    }


def _live_archive(tmp_path: Path) -> TaskArchive:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task(
        "task-safe", "raw prompt\n", pipeline_id="pipeline-initial"
    )
    archive.materialize_pipeline(
        "task-safe",
        {
            "pipelineId": "pipeline-initial",
            "taskId": "task-safe",
            "runs": [
                {
                    "runId": "run-implementation",
                    "role": "implementation",
                    "roleOrdinal": 1,
                    "state": "succeeded",
                    "path": "pipelines/pipeline-initial/runs/run-implementation/run.json",
                }
            ],
        },
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-implementation",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-public",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:02Z",
        },
    )
    pipeline_path = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/pipeline.json"
    )
    pipeline = json.loads(pipeline_path.read_text())
    pipeline["state"] = "succeeded"
    pipeline["completedAt"] = "2026-07-22T00:00:03Z"
    archive.write_json("task-safe", "pipelines/pipeline-initial/pipeline.json", pipeline)
    return archive


def test_effects_sidecar_is_bounded_canonical_and_tamper_evident(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-effects", "prompt", pipeline_id="pipeline-effects")
    proposal = EffectEvidence(
        task_id="task-effects",
        action=EffectActionKind.git_push,
        action_id="push-effects",
        mode=ExecutionMode.dry_run,
        decision=EffectDecisionKind.proposal_required,
        result=EffectResult.not_applied,
        proposal_id="proposal-" + "a" * 64,
    )
    path = archive.materialize_effects(
        "task-effects", [proposal], result=EffectResult.not_applied
    )
    first = path.read_bytes()
    assert first == archive.materialize_effects(
        "task-effects", [proposal], result=EffectResult.not_applied
    ).read_bytes()
    assert archive.effect_records("task-effects")[0]["proposalId"] == "proposal-" + "a" * 64
    path.write_bytes(first.replace(b"not-applied", b"applied"))
    with pytest.raises(ArchiveValidationError):
        archive.effect_records("task-effects")


def test_not_applicable_effects_sidecar_is_canonical_and_distinct_from_missing(
    tmp_path: Path,
) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-no-effects", "prompt", pipeline_id="pipeline-effects")
    path = archive.materialize_effects(
        "task-no-effects",
        (),
        result=EffectResult.not_applicable,
        mode=ExecutionMode.dry_run.value,
        recorded_at="2026-07-22T00:00:04Z",
    )
    first = path.read_bytes()
    assert first
    assert first == archive.materialize_effects(
        "task-no-effects",
        (),
        result=EffectResult.not_applicable,
        mode=ExecutionMode.dry_run.value,
        recorded_at="2026-07-22T00:00:04Z",
    ).read_bytes()
    records = archive.effect_records("task-no-effects")
    assert records == (
        {
            "action": "none",
            "actionId": "none",
            "at": "2026-07-22T00:00:04Z",
            "decision": "not-applicable",
            "effectId": records[0]["effectId"],
            "mode": "dry-run",
            "proposalId": None,
            "result": "not-applicable",
            "taskId": "task-no-effects",
        },
    )
    path.unlink()
    assert archive.effect_records("task-no-effects") == ()


def test_paths_reject_traversal_and_hidden_components(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    with pytest.raises(ArchiveValidationError):
        archive.task_dir("../task")
    with pytest.raises(ArchiveValidationError):
        archive.path("pipelines/.tmp/file")
    with pytest.raises(ArchiveValidationError):
        archive.path("pipelines\\run.json")


def _invocation_archive(tmp_path: Path) -> TaskArchive:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    archive.materialize_pipeline(
        "task-safe",
        {
            "pipelineId": "pipeline-initial",
            "taskId": "task-safe",
            "runs": [
                {
                    "runId": "run-safe",
                    "role": "implementation",
                    "roleOrdinal": 1,
                    "state": "running",
                    "path": "pipelines/pipeline-initial/runs/run-safe/run.json",
                }
            ],
        },
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "running",
        },
    )
    return archive


def test_collect_invocation_evidence_orders_retries_and_keeps_missing_partial(
    tmp_path: Path,
) -> None:
    archive = _invocation_archive(tmp_path)
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-1.json",
        _telemetry("task-safe", "invocation-first", 0),
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.json",
        _telemetry("task-safe", "invocation-final", 1),
    )
    values = archive.collect_invocation_evidence(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        expected_run={
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "runId": "run-safe",
            "role": "implementation",
        },
    )
    assert all(isinstance(item, ArchiveInvocation) for item in values)
    assert [item.retry_ordinal for item in values] == [0, 1]
    assert [item.invocation_id for item in values] == [
        "invocation-first",
        "invocation-final",
    ]
    assert all(item.aggregate is not None for item in values)

    archive.task_path(
        "task-safe",
        "pipelines/pipeline-initial/runs/run-safe/telemetry.json",
    ).unlink()
    partial = archive.collect_invocation_evidence(
        "task-safe", "pipeline-initial", "run-safe"
    )
    assert partial[-1].availability == "partial"
    assert partial[-1].aggregate is None


def test_collect_invocation_evidence_accepts_single_current_unavailable_marker(
    tmp_path: Path,
) -> None:
    archive = _invocation_archive(tmp_path)
    marker_path = archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.unavailable-1.json",
        {"availability": "unavailable", "reason": "failed"},
    )

    values = archive.collect_invocation_evidence(
        "task-safe", "pipeline-initial", "run-safe"
    )

    assert len(values) == 1
    evidence = values[0]
    assert evidence.invocation_id is None
    assert evidence.retry_ordinal == 0
    assert evidence.availability == "partial"
    assert evidence.completeness == "unavailable"
    assert evidence.reason == "failed"
    assert evidence.byte_size == marker_path.stat().st_size
    assert evidence.content_digest == hashlib.sha256(
        marker_path.read_bytes()
    ).hexdigest()


def test_collect_invocation_evidence_rejects_ordinal_gaps_and_keeps_unavailable(
    tmp_path: Path,
) -> None:
    archive = _invocation_archive(tmp_path)
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-1.json",
        _telemetry("task-safe", "invocation-first", 0),
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-3.json",
        _telemetry("task-safe", "invocation-third", 2),
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.json",
        _telemetry("task-safe", "invocation-final", 3),
    )
    with pytest.raises(ArchiveValidationError, match="gaps"):
        archive.collect_invocation_evidence(
            "task-safe", "pipeline-initial", "run-safe"
        )

    archive.task_path(
        "task-safe",
        "pipelines/pipeline-initial/runs/run-safe/telemetry.retry-3.json",
    ).unlink()
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-2.json",
        {"availability": "unavailable", "reason": "interrupted"},
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-3.json",
        _telemetry("task-safe", "invocation-third", 2),
    )
    values = archive.collect_invocation_evidence(
        "task-safe", "pipeline-initial", "run-safe"
    )
    assert [item.retry_ordinal for item in values] == [0, 1, 2, 3]
    assert values[1].availability == "partial"
    assert values[1].reason == "interrupted"


def test_collect_invocation_evidence_rejects_symlink_and_conflicting_identity(
    tmp_path: Path,
) -> None:
    archive = _invocation_archive(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_telemetry("task-safe", "outside", 0)))
    sidecar = archive.task_path(
        "task-safe",
        "pipelines/pipeline-initial/runs/run-safe/telemetry.json",
    )
    sidecar.symlink_to(outside)
    with pytest.raises(ArchiveValidationError):
        archive.collect_invocation_evidence(
            "task-safe", "pipeline-initial", "run-safe"
        )
    sidecar.unlink()
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-1.json",
        _telemetry("task-safe", "same-id", 0),
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.json",
        _telemetry("task-safe", "same-id", 1),
    )
    with pytest.raises(ArchiveValidationError, match="conflicting"):
        archive.collect_invocation_evidence(
            "task-safe", "pipeline-initial", "run-safe"
        )


def test_run_invocation_count_is_bounded(tmp_path: Path) -> None:
    archive = _invocation_archive(tmp_path)
    run_dir = archive.run_dir("task-safe", "pipeline-initial", "run-safe")
    for ordinal in range(1, MAX_ARCHIVE_INVOCATIONS + 2):
        path = run_dir / f"telemetry.retry-{ordinal}.json"
        path.write_text(
            json.dumps(_telemetry("task-safe", f"invocation-{ordinal}", ordinal - 1)),
            encoding="utf-8",
        )
    with pytest.raises(ArchiveValidationError, match="count exceeds bound"):
        archive.collect_invocation_evidence(
            "task-safe", "pipeline-initial", "run-safe"
        )


def test_manifest_round_trip_keeps_failed_interrupted_and_final_retry_sidecars(
    tmp_path: Path,
) -> None:
    archive = _invocation_archive(tmp_path)
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-1.json",
        _telemetry("task-safe", "failed-retry", 0, process_outcome="failed"),
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.retry-2.json",
        _telemetry(
            "task-safe", "interrupted-retry", 1, process_outcome="interrupted"
        ),
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.json",
        _telemetry("task-safe", "successful-final", 2),
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:02Z",
        },
    )
    pipeline_path = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/pipeline.json"
    )
    pipeline = json.loads(pipeline_path.read_text())
    pipeline["state"] = "succeeded"
    pipeline["phase"] = "complete"
    pipeline["completedAt"] = "2026-07-22T00:00:03Z"
    archive.write_json("task-safe", "pipelines/pipeline-initial/pipeline.json", pipeline)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    manifest = archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-retries",
        completed_at=COMPLETED_AT,
        external_actions_complete=True,
        writer_final=True,
    )
    assert archive.verify("task-safe")
    manifest_value = json.loads(manifest.read_text())
    paths = {item["path"] for item in manifest_value["files"]}
    assert {
        "task-safe/pipelines/pipeline-initial/runs/run-safe/telemetry.retry-1.json",
        "task-safe/pipelines/pipeline-initial/runs/run-safe/telemetry.retry-2.json",
        "task-safe/pipelines/pipeline-initial/runs/run-safe/telemetry.json",
    }.issubset({f"task-safe/{path}" for path in paths})


def test_seal_rejects_persisted_invocation_descriptor_mismatch(
    tmp_path: Path,
) -> None:
    archive = _invocation_archive(tmp_path)
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.json",
        _telemetry("task-safe", "invocation-final", 0),
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:02Z",
        },
    )
    pipeline_path = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/pipeline.json"
    )
    pipeline = json.loads(pipeline_path.read_text())
    pipeline["state"] = "succeeded"
    pipeline["phase"] = "complete"
    pipeline["completedAt"] = "2026-07-22T00:00:03Z"
    archive.write_json("task-safe", "pipelines/pipeline-initial/pipeline.json", pipeline)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)

    archive.task_path(
        "task-safe",
        "pipelines/pipeline-initial/runs/run-safe/telemetry.json",
    ).unlink()
    with pytest.raises(ArchiveSealError, match="invocation descriptors"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-descriptor-mismatch",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )


def test_seal_rejects_equal_size_sidecar_replacement(tmp_path: Path) -> None:
    archive = _invocation_archive(tmp_path)
    original = _telemetry("task-safe", "invocation-final", 0)
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.json",
        original,
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:02Z",
        },
    )
    replacement = dict(original)
    replacement["reasoning_effort"] = "mid"
    sidecar = archive.task_path(
        "task-safe",
        "pipelines/pipeline-initial/runs/run-safe/telemetry.json",
    )
    replacement_bytes = (
        json.dumps(replacement, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    assert len(replacement_bytes) == sidecar.stat().st_size
    sidecar.write_bytes(replacement_bytes)

    pipeline_path = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/pipeline.json"
    )
    pipeline = json.loads(pipeline_path.read_text())
    pipeline["state"] = "succeeded"
    pipeline["phase"] = "complete"
    pipeline["completedAt"] = "2026-07-22T00:00:03Z"
    archive.write_json("task-safe", "pipelines/pipeline-initial/pipeline.json", pipeline)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)

    with pytest.raises(ArchiveSealError, match="invocation descriptors"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-equal-size-replacement",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )


def test_seal_rejects_conflicting_current_unavailable_markers(tmp_path: Path) -> None:
    archive = _invocation_archive(tmp_path)
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.unavailable-1.json",
        {"availability": "unavailable", "reason": "failed"},
    )
    archive.write_run_file(
        "task-safe",
        "pipeline-initial",
        "run-safe",
        "telemetry.unavailable-2.json",
        {"availability": "unavailable", "reason": "interrupted"},
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:02Z",
        },
    )
    pipeline_path = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/pipeline.json"
    )
    pipeline = json.loads(pipeline_path.read_text())
    pipeline["state"] = "succeeded"
    pipeline["phase"] = "complete"
    pipeline["completedAt"] = "2026-07-22T00:00:03Z"
    archive.write_json("task-safe", "pipelines/pipeline-initial/pipeline.json", pipeline)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)

    with pytest.raises(ArchiveSealError, match="invocation evidence"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-conflicting-current-markers",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )


def test_atomic_materialization_and_exact_reconciliation(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    assert archive.reconcile("task-safe", "result.json", b"{}\n") == "materialized"
    assert archive.reconcile("task-safe", "result.json", b"{}\n") == "adopted"
    with pytest.raises(ArchiveConflictError):
        archive.reconcile("task-safe", "result.json", b"different\n")


def test_jsonl_appends_complete_lines_only(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    archive.append_event("task-safe", {"kind": "task.created"})
    events = archive.task_path("task-safe", "events.jsonl").read_bytes()
    assert events.endswith(b"\n")
    archive.task_path("task-safe", "events.jsonl").write_bytes(events + b"incomplete")
    with pytest.raises(ArchiveConflictError):
        archive.append_event("task-safe", {"kind": "blocked"})


def test_jsonl_event_id_retry_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    timestamps = iter(
        [
            "2026-07-22T00:00:00Z",
            "2026-07-22T00:01:00Z",
            "2026-07-22T00:02:00Z",
        ]
    )
    monkeypatch.setattr(
        "coquic_steward.execution.task_archive._now", lambda: next(timestamps)
    )
    event = {
        "eventId": "event-stable",
        "kind": "task.created",
    }

    first_offset = archive.append_event("task-safe", event)
    second_offset = archive.append_event("task-safe", event)

    assert second_offset == first_offset
    assert len(archive.task_path("task-safe", "events.jsonl").read_text().splitlines()) == 1
    with pytest.raises(ArchiveConflictError, match="eventId"):
        archive.append_event("task-safe", {**event, "kind": "task.failed"})


def test_private_fields_do_not_enter_run_metadata(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "sessionId": "session-safe",
            "providerSessionId": "private-provider",
            "privateHomePath": "/private/codex",
        },
    )
    text = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/runs/run-safe/run.json"
    ).read_text()
    assert "private-provider" not in text
    assert "/private/codex" not in text


def test_seal_manifest_is_exact_and_terminal(tmp_path: Path) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    manifest = archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-safe",
        completed_at=COMPLETED_AT,
        external_actions_complete=True,
        writer_final=True,
    )
    assert archive.verify("task-safe")
    assert manifest.exists()
    with pytest.raises(ArchiveImmutableError):
        archive.write_json("task-safe", "task.json", task)
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    assert not archive.verify("task-safe")


def test_delete_verified_removes_only_one_sealed_direct_child(tmp_path: Path) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-delete",
        completed_at=COMPLETED_AT,
        external_actions_complete=True,
        writer_final=True,
    )
    sibling = archive.root / "task-sibling"
    sibling.mkdir()
    (sibling / "evidence").write_text("retain\n", encoding="utf-8")

    assert archive.delete_verified("task-safe") == "deleted"
    assert not archive.task_dir("task-safe").exists()
    assert (sibling / "evidence").read_text(encoding="utf-8") == "retain\n"
    with pytest.raises(ArchiveValidationError, match="absent"):
        archive.delete_verified("task-safe")
    assert archive.delete_verified("task-safe", allow_absent=True) == "absent"


def test_delete_verified_binds_expected_manifest_before_removal(tmp_path: Path) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-delete-binding",
        completed_at=COMPLETED_AT,
        external_actions_complete=True,
        writer_final=True,
    )

    with pytest.raises(ArchiveConflictError, match="deletion intent"):
        archive.delete_verified("task-safe", expected_digest="0" * 64)
    assert archive.task_dir("task-safe").is_dir()


@pytest.mark.parametrize("task_id", [".", "..", "task/other", "task*"])
def test_delete_verified_rejects_non_exact_task_ids(tmp_path: Path, task_id: str) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    with pytest.raises(ArchiveValidationError):
        archive.delete_verified(task_id)


def test_delete_verified_rejects_symlink_task_child(tmp_path: Path) -> None:
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (tasks / "task-safe").symlink_to(outside, target_is_directory=True)
    archive = TaskArchive(tasks)

    with pytest.raises(ArchiveValidationError, match="symlink"):
        archive.delete_verified("task-safe")
    assert outside.exists()


def test_seal_requires_caller_finality(tmp_path: Path) -> None:
    archive = _live_archive(tmp_path)
    with pytest.raises(ArchiveSealError):
        archive.seal("task-safe", "succeeded")


def test_task_directory_symlink_is_rejected(tmp_path: Path) -> None:
    tasks = tmp_path / "tasks"
    outside = tmp_path / "outside"
    tasks.mkdir()
    outside.mkdir()
    (tasks / "task-safe").symlink_to(outside, target_is_directory=True)

    archive = TaskArchive(tasks)
    with pytest.raises(ArchiveValidationError, match="symlink"):
        archive.create_task(
            "task-safe", "prompt", pipeline_id="pipeline-initial"
        )
    assert not (outside / "task.json").exists()


def test_seal_rejects_symlinked_directory(tmp_path: Path) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    outside = tmp_path / "outside"
    outside.mkdir()
    archive.task_path("task-safe", "linked").symlink_to(
        outside, target_is_directory=True
    )

    with pytest.raises(ArchiveSealError, match="symlink"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-safe",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )


def test_writes_and_seal_reject_special_files(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    fifo = archive.task_path("task-safe", "result.json")
    os.mkfifo(fifo)

    with pytest.raises(ArchiveValidationError, match="regular file"):
        archive.reconcile("task-safe", "result.json", b"{}\n")
    with pytest.raises(ArchiveSealError, match="non-regular"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-safe",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )


def test_materializers_emit_canonical_pipeline_and_run_shapes(
    tmp_path: Path,
) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    pipeline_path = archive.materialize_pipeline(
        "task-safe",
        {
            "pipelineId": "pipeline-initial",
            "taskId": "task-safe",
            "runs": [
                {
                    "runId": "run-safe",
                    "role": "implementation",
                    "roleOrdinal": 1,
                    "state": "succeeded",
                    "path": "pipelines/pipeline-initial/runs/run-safe/run.json",
                }
            ],
        },
    )
    run_path = archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:00Z",
            "exit_code": 0,
            "exit_reason": "complete",
            "result_summary": "done",
            "idempotency_key": "private-key",
        },
    )

    pipeline = json.loads(pipeline_path.read_text())
    run = json.loads(run_path.read_text())
    assert pipeline["integration"]["state"] == "pending"
    assert run["exit"] == {"code": 0, "reason": "complete", "signal": None}
    assert run["result"]["summary"] == "done"
    assert not ({"exit_code", "exit_reason", "result_summary", "idempotency_key"} & run.keys())


def test_seal_schema_validates_pipeline_documents(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    archive.materialize_pipeline(
        "task-safe",
        {
            "pipelineId": "pipeline-initial",
            "taskId": "task-safe",
            "runs": [
                {
                    "runId": "run-safe",
                    "role": "implementation",
                    "roleOrdinal": 1,
                    "state": "succeeded",
                    "path": "pipelines/pipeline-initial/runs/run-safe/run.json",
                }
            ],
        },
    )
    archive.materialize_run(
        "task-safe",
        "pipeline-initial",
        {
            "runId": "run-safe",
            "taskId": "task-safe",
            "pipelineId": "pipeline-initial",
            "role": "implementation",
            "roleOrdinal": 1,
            "sessionId": "session-safe",
            "state": "succeeded",
            "completedAt": "2026-07-22T00:00:00Z",
        },
    )
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    pipeline_path = archive.task_path(
        "task-safe", "pipelines/pipeline-initial/pipeline.json"
    )
    pipeline = json.loads(pipeline_path.read_text())
    pipeline.pop("integration", None)
    pipeline["state"] = "succeeded"
    pipeline["completedAt"] = "2026-07-22T00:00:01Z"
    archive.write_json(
        "task-safe", "pipelines/pipeline-initial/pipeline.json", pipeline
    )

    with pytest.raises(ArchiveSealError, match="pipeline schema"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-safe",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("epochId", "epoch-wrong"),
        ("completionIdentity", "unsafe/path"),
        ("terminalStatus", "running"),
        ("completedAt", "never"),
    ],
)
def test_manifest_verification_rejects_invalid_identity_and_epoch(
    tmp_path: Path, field: str, value: str
) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    manifest_path = archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-safe",
        completed_at=COMPLETED_AT,
        external_actions_complete=True,
        writer_final=True,
    )
    manifest = json.loads(manifest_path.read_text())
    manifest[field] = value
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    assert not archive.verify("task-safe")


def test_materializes_typed_ledger_with_real_ids_and_exact_terminal_retries(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="typed ledger",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(
        task.id, pipeline.id, session.id, role="implementation"
    )
    archive = TaskArchive(config.tasks_dir)

    archive.materialize_ledger(task, pipeline, [run])
    archive.materialize_ledger(task, pipeline, [run])

    task_document = json.loads(archive.task_path(task.id, "task.json").read_text())
    assert task_document["currentPipelineId"] == pipeline.id
    assert task_document["pipelines"][0]["pipelineId"] == pipeline.id
    pipeline_path = archive.task_path(
        task.id, f"pipelines/{pipeline.id}/pipeline.json"
    )
    assert json.loads(pipeline_path.read_text())["state"] == "active"

    completed_run = store.transition_run(run.id, "succeeded", exit_code=0)
    archive.materialize_run(task.id, pipeline.id, completed_run)
    completed_pipeline = store.transition_pipeline(
        pipeline.id, "succeeded", phase="complete"
    )
    archive.materialize_pipeline(
        task.id, completed_pipeline, runs=[completed_run]
    )

    archive.materialize_run(task.id, pipeline.id, completed_run)
    archive.materialize_pipeline(
        task.id, completed_pipeline, runs=[completed_run]
    )
    with pytest.raises(ArchiveImmutableError):
        archive.materialize_pipeline(
            task.id,
            completed_pipeline.model_copy(update={"output_identity": "changed"}),
            runs=[completed_run],
        )


def test_materialize_run_rejects_model_dump_lookalike_without_mutation(
    tmp_path: Path,
) -> None:
    class ModelDumpLookalike:
        called = False

        def model_dump(self, **_kwargs: object) -> dict[str, object]:
            self.called = True
            raise AssertionError("unsupported serializer executed")

    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt", pipeline_id="pipeline-initial")
    before = {
        path.relative_to(archive.root): path.read_bytes()
        for path in archive.root.rglob("*")
        if path.is_file()
    }
    lookalike = ModelDumpLookalike()

    with pytest.raises(TypeError, match="expected mapping or pydantic model"):
        archive.materialize_run(  # type: ignore[arg-type]
            "task-safe", "pipeline-initial", lookalike
        )

    after = {
        path.relative_to(archive.root): path.read_bytes()
        for path in archive.root.rglob("*")
        if path.is_file()
    }
    assert lookalike.called is False
    assert after == before


def test_create_task_rejects_model_dump_lookalike_before_mutation(
    tmp_path: Path,
) -> None:
    class ModelDumpLookalike:
        called = False

        def model_dump(self, **_kwargs: object) -> dict[str, object]:
            self.called = True
            raise AssertionError("unsupported serializer executed")

    archive = TaskArchive(tmp_path / "tasks")
    lookalike = ModelDumpLookalike()

    with pytest.raises(TypeError, match="expected mapping or pydantic model"):
        archive.create_task(  # type: ignore[arg-type]
            "task-safe",
            "prompt",
            task=lookalike,
            pipeline_id="pipeline-initial",
        )

    assert lookalike.called is False
    assert not archive.root.exists()
    assert not archive.epoch_path.exists()
    assert not archive.task_dir("task-safe").exists()


def test_materialize_ledger_rejects_model_dump_lookalike_before_mutation(
    tmp_path: Path,
) -> None:
    store = TaskStore.create(tmp_path / "store.sqlite")
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="typed ledger",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(task.id, pipeline.id, session.id, role="implementation")

    class ModelDumpLookalike:
        called = False

        def __init__(self) -> None:
            self.id = pipeline.id
            self.task_id = task.id

        def model_dump(self, **_kwargs: object) -> dict[str, object]:
            self.called = True
            raise AssertionError("unsupported serializer executed")

    archive = TaskArchive(tmp_path / "archive")
    lookalike = ModelDumpLookalike()

    with pytest.raises(TypeError, match="expected mapping or pydantic model"):
        archive.materialize_ledger(  # type: ignore[arg-type]
            task,
            lookalike,
            [run],
        )

    assert lookalike.called is False
    assert not archive.root.exists()
    assert not archive.epoch_path.exists()
    assert not archive.task_dir(task.id).exists()


def test_task_materialization_requires_a_ledger_pipeline_id(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")

    with pytest.raises(ArchiveValidationError, match="ledger pipeline"):
        archive.create_task("task-safe", "prompt")


def test_seal_is_single_winner_and_binds_completion_envelope(tmp_path: Path) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    requests = [
        ("completion-one", "2026-07-22T00:01:00Z"),
        ("completion-two", "2026-07-22T00:02:00Z"),
    ]

    def seal(request: tuple[str, str]) -> tuple[str, object]:
        try:
            return (
                "sealed",
                TaskArchive(archive.root).seal(
                    "task-safe",
                    "succeeded",
                    completion_identity=request[0],
                    completed_at=request[1],
                    external_actions_complete=True,
                    writer_final=True,
                ),
            )
        except ArchiveConflictError as exc:
            return "conflict", exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(seal, requests))

    assert sorted(result[0] for result in results) == ["conflict", "sealed"]
    manifest_path = archive.task_path("task-safe", "manifest.json")
    manifest = json.loads(manifest_path.read_text())
    winning_request = (
        manifest["completionIdentity"],
        manifest["completedAt"],
    )
    assert winning_request in requests
    assert archive.verify("task-safe")
    assert (
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity=winning_request[0],
            completed_at=winning_request[1],
            external_actions_complete=True,
            writer_final=True,
        )
        == manifest_path
    )

    manifest["completionIdentity"] = "completion-recanonicalized"
    manifest["completedAt"] = "2026-07-22T00:03:00Z"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    assert not archive.verify("task-safe")


def test_seal_crash_retries_only_the_exact_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    real_create = archive._atomic_create_bytes

    def crash(path: Path, data: bytes) -> bool:
        if path.name == "manifest.json":
            raise RuntimeError("injected seal crash")
        return real_create(path, data)

    monkeypatch.setattr(archive, "_atomic_create_bytes", crash)
    with pytest.raises(RuntimeError, match="seal crash"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-stable",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )
    monkeypatch.setattr(archive, "_atomic_create_bytes", real_create)

    with pytest.raises(ArchiveConflictError, match="completion"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-different",
            completed_at=COMPLETED_AT,
            external_actions_complete=True,
            writer_final=True,
        )
    archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-stable",
        completed_at=COMPLETED_AT,
        external_actions_complete=True,
        writer_final=True,
    )
    assert archive.verify("task-safe")


def test_seal_crash_before_completion_event_keeps_retry_consistent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _live_archive(tmp_path)
    task_path = archive.task_path("task-safe", "task.json")
    task = json.loads(task_path.read_text())
    task["status"] = "succeeded"
    archive.write_json("task-safe", "task.json", task)
    real_append = archive.append_event

    def crash(task_id: str, event: Mapping[str, Any]) -> int:
        if event.get("kind") == "archive.frozen":
            raise RuntimeError("injected completion event crash")
        return real_append(task_id, event)

    monkeypatch.setattr(archive, "append_event", crash)
    with pytest.raises(RuntimeError, match="completion event crash"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-first",
            completed_at="2026-07-22T00:01:00Z",
            external_actions_complete=True,
            writer_final=True,
        )
    monkeypatch.setattr(archive, "append_event", real_append)

    archive.seal(
        "task-safe",
        "succeeded",
        completion_identity="completion-second",
        completed_at="2026-07-22T00:02:00Z",
        external_actions_complete=True,
        writer_final=True,
    )
    manifest = json.loads(
        archive.task_path("task-safe", "manifest.json").read_text()
    )
    task = json.loads(task_path.read_text())
    assert manifest["completionIdentity"] == "completion-second"
    assert task["terminalStatusObservedAt"] == manifest["completedAt"]
    assert archive.verify("task-safe")


@pytest.mark.parametrize("cleared_field", [None, "reviews", "validations", "runs"])
def test_pipeline_ledger_refresh_preserves_archive_graph_through_seal(
    config: StewardConfig, cleared_field: str | None
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="archive graph refresh",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(task.id, pipeline.id, session.id, role="implementation")
    archive = TaskArchive(config.tasks_dir)
    archive.materialize_ledger(task, pipeline, [run])
    archive.materialize_review(
        task.id, pipeline.id,
        {"reviewId": "review-safe", "state": "available", "verdict": "approve"},
    )
    validation_path = archive.materialize_validation(
        task.id, pipeline.id,
        {
            "validationId": "validation-safe",
            "command": "pytest",
            "state": "completed",
            "result": "pass",
            "completedAt": COMPLETED_AT,
        },
        output="passed\n",
    )
    descriptor = json.loads(validation_path.read_text())["output"]
    relative = f"pipelines/{pipeline.id}/pipeline.json"
    path = archive.task_path(task.id, relative)
    document = json.loads(path.read_text())
    document.update(
        inputs=[descriptor], patches=[descriptor],
        integration={
            "state": "succeeded", "resultPath": None, "commit": "a" * 40,
            "startedAt": document["startedAt"], "completedAt": COMPLETED_AT,
        },
    )
    archive.materialize_pipeline(task.id, document)
    graph_fields = ("inputs", "patches", "validations", "reviews", "runs", "integration")
    expected = {key: document[key] for key in graph_fields}

    # Both ledger refresh APIs must retain references created by archive writers.
    for _ in range(2):
        archive.materialize_ledger(task, pipeline, [run])
        archive.materialize_pipeline(task.id, pipeline)
        assert {key: json.loads(path.read_text())[key] for key in graph_fields} == expected

    completed_run = store.transition_run(run.id, "succeeded", exit_code=0)
    archive.materialize_run(task.id, pipeline.id, completed_run)
    completed_pipeline = store.transition_pipeline(pipeline.id, "succeeded", phase="complete")
    # A supplied ledger wins over both an incoming runs field and retained runs.
    incoming = pipeline.model_dump(mode="json")
    incoming["runs"] = []
    archive.materialize_pipeline(task.id, incoming, runs=[completed_run])
    assert json.loads(path.read_text())["runs"][0]["state"] == "succeeded"

    terminal = completed_pipeline.model_dump(mode="json")
    if cleared_field == "runs":
        archive.materialize_pipeline(task.id, terminal, runs=[])
    else:
        if cleared_field is not None:
            terminal[cleared_field] = []
        archive.materialize_pipeline(task.id, terminal, runs=[completed_run])
    for _ in range(2):
        archive.materialize_pipeline(task.id, completed_pipeline)
        if cleared_field is None:
            archive.materialize_pipeline(task.id, completed_pipeline, runs=[completed_run])
    terminal = json.loads(path.read_text())
    if cleared_field is not None:
        assert terminal[cleared_field] == []
    for key in graph_fields:
        if key != "runs" and key != cleared_field:
            assert terminal[key] == expected[key]

    task_document = json.loads(archive.task_path(task.id, "task.json").read_text())
    task_document["status"] = "succeeded"
    archive.write_json(task.id, "task.json", task_document)
    seal_kwargs = dict(
        completion_identity="completion-safe", completed_at=COMPLETED_AT,
        external_actions_complete=True, writer_final=True,
    )
    if cleared_field is None:
        archive.seal(task.id, "succeeded", **seal_kwargs)
        assert archive.verify(task.id)
    else:
        label = {"reviews": "review", "validations": "validation", "runs": "run"}[cleared_field]
        with pytest.raises(ArchiveSealError, match=f"{label} graph coverage is not exact"):
            archive.seal(task.id, "succeeded", **seal_kwargs)
        assert not archive.task_path(task.id, "manifest.json").exists()


@pytest.mark.parametrize(
    "corruption", ["json", "utf8", "shape", "references", "taskId", "pipelineId", "symlink", "dangling", "parent", "directory"]
)
def test_pipeline_refresh_rejects_invalid_existing_metadata_without_mutation(
    tmp_path: Path, corruption: str
) -> None:
    archive = _invocation_archive(tmp_path)
    path = archive.task_path("task-safe", "pipelines/pipeline-initial/pipeline.json")
    incoming = json.loads(path.read_text())
    if corruption == "json":
        path.write_text("{")
    elif corruption == "utf8":
        path.write_bytes(b"\xff")
    elif corruption == "shape":
        path.write_text("[]")
    elif corruption == "references":
        path.write_text(json.dumps(dict(incoming, reviews=[{"path": "../outside"}])))
    elif corruption in {"taskId", "pipelineId"}:
        path.write_text(json.dumps(dict(incoming, **{corruption: "wrong-identity"})))
    elif corruption == "parent":
        outside = tmp_path / "outside"
        path.parent.rename(outside)
        path.parent.symlink_to(outside, target_is_directory=True)
    else:
        original = path.read_bytes()
        path.unlink()
        if corruption == "directory":
            path.mkdir()
        else:
            outside = tmp_path / "outside.json"
            if corruption == "symlink":
                outside.write_bytes(original)
            path.symlink_to(outside)
    task_path = archive.task_path("task-safe", "task.json")
    task_before = task_path.read_bytes()
    before = path.read_bytes() if path.is_file() else None
    error = ArchiveConflictError if corruption in {"taskId", "pipelineId"} else ArchiveValidationError
    # Even a complete incoming document must not silently repair corrupt metadata.
    with pytest.raises(error):
        archive.materialize_pipeline("task-safe", incoming)
    assert task_path.read_bytes() == task_before
    assert (path.read_bytes() if path.is_file() else None) == before
    if corruption in {"symlink", "dangling"}:
        assert path.is_symlink()
    if corruption == "parent":
        assert path.parent.is_symlink()

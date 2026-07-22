from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from coquic_steward.execution.task_archive import (
    ArchiveConflictError,
    ArchiveImmutableError,
    ArchiveSealError,
    ArchiveValidationError,
    TaskArchive,
)


def _live_archive(tmp_path: Path) -> TaskArchive:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "raw prompt\n")
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


def test_paths_reject_traversal_and_hidden_components(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    with pytest.raises(ArchiveValidationError):
        archive.task_dir("../task")
    with pytest.raises(ArchiveValidationError):
        archive.path("pipelines/.tmp/file")
    with pytest.raises(ArchiveValidationError):
        archive.path("pipelines\\run.json")


def test_atomic_materialization_and_exact_reconciliation(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt")
    assert archive.reconcile("task-safe", "result.json", b"{}\n") == "materialized"
    assert archive.reconcile("task-safe", "result.json", b"{}\n") == "adopted"
    with pytest.raises(ArchiveConflictError):
        archive.reconcile("task-safe", "result.json", b"different\n")


def test_jsonl_appends_complete_lines_only(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt")
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
    archive.create_task("task-safe", "prompt")
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
    archive.create_task("task-safe", "prompt")
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
        external_actions_complete=True,
        writer_final=True,
    )
    assert archive.verify("task-safe")
    assert manifest.exists()
    with pytest.raises(ArchiveImmutableError):
        archive.write_json("task-safe", "task.json", task)
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    assert not archive.verify("task-safe")


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
        archive.create_task("task-safe", "prompt")
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
            external_actions_complete=True,
            writer_final=True,
        )


def test_writes_and_seal_reject_special_files(tmp_path: Path) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt")
    fifo = archive.task_path("task-safe", "result.json")
    os.mkfifo(fifo)

    with pytest.raises(ArchiveValidationError, match="regular file"):
        archive.reconcile("task-safe", "result.json", b"{}\n")
    with pytest.raises(ArchiveSealError, match="non-regular"):
        archive.seal(
            "task-safe",
            "succeeded",
            completion_identity="completion-safe",
            external_actions_complete=True,
            writer_final=True,
        )


def test_materializers_emit_canonical_pipeline_and_run_shapes(
    tmp_path: Path,
) -> None:
    archive = TaskArchive(tmp_path / "tasks")
    archive.create_task("task-safe", "prompt")
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
    archive.create_task("task-safe", "prompt")
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

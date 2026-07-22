from __future__ import annotations

import json
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

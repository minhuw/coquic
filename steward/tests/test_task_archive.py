from __future__ import annotations

import json
import os
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from coquic_steward.execution.task_archive import (
    ArchiveConflictError,
    ArchiveImmutableError,
    ArchiveSealError,
    ArchiveValidationError,
    TaskArchive,
)
from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
from coquic_steward.storage import TaskStore


COMPLETED_AT = "2026-07-22T00:00:04Z"


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
    store = TaskStore(config.db_path)
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

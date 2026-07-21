from __future__ import annotations

import copy
import json
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Any

import pytest

from coquic_steward.core.config import PublicMirrorConfig, StewardConfig
from coquic_steward.core.models import (
    DaemonRuntime,
    DaemonRuntimeState,
    PublicMirrorFailureCategory,
    PublicMirrorHealth,
    PublicMirrorPublishState,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    TaskKind,
    TaskSpec,
    TaskStatus,
    ValidationResult,
    WorkerKind,
    WorkerResult,
)
from coquic_steward.public_mirror import (
    MIRROR_TRAJECTORY_AGGREGATE_PATCH_BYTES,
    MIRROR_TRAJECTORY_PATCH_BYTES,
    _public_change_trajectory,
    _trajectory_redacted_patch,
    public_mirror_digest,
    public_mirror_payload,
    public_task_detail_payload,
)
from coquic_steward.storage import TaskStore
from steward.schema.validate import (
    FIXTURE_DIR,
    SchemaValidationError,
    load_schema,
    validate_public_monitor,
)

FIXED_TIME = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
EXPECTED_FIXTURES = {
    "active.json",
    "blocked.json",
    "empty.json",
    "failed.json",
    "idle.json",
    "integration.json",
    "stale.json",
}
PRIVATE_MARKERS = (
    "/home/",
    "/media/",
    "/tmp/",
    "BEGIN PRIVATE KEY",
    "contract-seeded-secret",
    "private-thread",
    "api_key",
    "Authorization: Bearer",
)
ARTIFACT_REQUIRED = {
    "availability",
    "mode",
    "text",
    "size_bytes",
    "original_size_bytes",
    "truncated",
}


def _contract_config(config: StewardConfig, *, publish: bool = False) -> StewardConfig:
    return replace(
        config,
        enabled_signals=(),
        signal_providers={},
        integration_mode="local-only",
        local_only=True,
        public_mirror=PublicMirrorConfig(
            enabled=publish,
            publish=publish,
            transcript_mode="redacted",
        ),
    )


def _add_task(
    store: TaskStore,
    *,
    task_id: str,
    status: TaskStatus = TaskStatus.queued,
    kind: TaskKind = TaskKind.custom,
    worker: WorkerKind = WorkerKind.custom,
    metadata: dict[str, Any] | None = None,
) -> Any:
    task, created = store.add_task(
        TaskSpec(
            id=task_id,
            kind=kind,
            worker=worker,
            title=f"Contract task {task_id}",
            prompt="private prompt /home/contract-private/prompt.md",
            metadata=metadata or {},
        )
    )
    assert created
    if status == TaskStatus.running:
        task = store.start_worker(task.id, "running contract task")
    elif status == TaskStatus.reviewing:
        store.start_worker(task.id, "review contract task")
        task = store.start_review(task.id, "reviewing contract task")
    elif status == TaskStatus.integrating:
        task = store.start_integration(task.id, "integrating contract task")
    elif status.terminal:
        task = store.finish_task(task.id, status, f"{status.value} contract task")
    else:
        assert status == TaskStatus.queued
    return task


def _health(
    state: PublicMirrorPublishState,
    *,
    category: PublicMirrorFailureCategory | None = None,
) -> PublicMirrorHealth:
    digest = "a" * 64
    return PublicMirrorHealth(
        state=state,
        snapshot_id=digest,
        generated_at=FIXED_TIME,
        last_attempt_at=FIXED_TIME + timedelta(seconds=1),
        last_success_at=(
            FIXED_TIME + timedelta(seconds=2)
            if state == PublicMirrorPublishState.published
            else None
        ),
        last_failure_at=(
            FIXED_TIME + timedelta(seconds=2)
            if state == PublicMirrorPublishState.failed
            else None
        ),
        last_failure_category=category,
        retry_count=2 if state == PublicMirrorPublishState.failed else 0,
        last_accepted_digest=(digest if state == PublicMirrorPublishState.published else None),
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _worker_result(config: StewardConfig, transcript: Path, last_message: Path) -> WorkerResult:
    return WorkerResult(
        completed=True,
        command=["codex", "run"],
        cwd=config.repo_root,
        exit_code=0,
        transcript_path=transcript,
        last_message_path=last_message,
        final_message="contract result",
        model="contract-model",
        reasoning_effort="low",
    )


def _populate_detail_records(config: StewardConfig, store: TaskStore) -> tuple[Any, Any]:
    source = _add_task(
        store,
        task_id="task-20260713120000-source1",
        status=TaskStatus.succeeded,
        kind=TaskKind.feature,
        worker=WorkerKind.feature_implementer,
        metadata={"evidence": {"api_key": "contract-seeded-secret"}},
    )
    integration = _add_task(
        store,
        task_id="task-20260713120001-integ1",
        status=TaskStatus.integrating,
        kind=TaskKind.integration,
        worker=WorkerKind.integration_manager,
        metadata={
            "source_task_id": source.id,
            "main_commit": "b" * 40,
            "evidence": {"private_thread": "private-thread"},
        },
    )

    task_dir = config.state_dir / "tasks" / integration.id
    transcript = _write(
        config.transcripts_dir / integration.id / "codex.jsonl",
        '{"type":"item.completed","item":{"type":"agent_message","text":"api_key=contract-seeded-secret /home/contract-private/key.pem"}}\n',
    )
    last_message = _write(
        config.transcripts_dir / integration.id / "last-message.md",
        "Authorization: Bearer contract-seeded-secret\n",
    )
    patch = _write(
        config.patches_dir / f"{integration.id}.patch",
        "diff --git a/src/example.cc b/src/example.cc\n+safe patch\n",
    )
    validation_log = _write(
        config.logs_dir / integration.id / "validation.txt",
        "/home/contract-private/worktree\napi_key=contract-seeded-secret\n",
    )
    record = store.get(integration.id)
    record.transcript_path = transcript
    record.last_message_path = last_message
    record.patch_path = patch
    record.summary = "Authorization: Bearer contract-seeded-secret"
    store.save(record)

    validation = ValidationResult(
        command=["nix", "develop", "--command", "secret-check"],
        cwd=config.repo_root,
        passed=False,
        exit_code=1,
        output_path=validation_log,
        summary="api_key=contract-seeded-secret",
        iteration=0,
    )
    store.record_iteration_validations(integration.id, 0, [validation])

    worker_transcript = _write(
        config.transcripts_dir / integration.id / "worker" / "codex.jsonl",
        '{"type":"item.completed","item":{"type":"agent_message","text":"worker /home/contract-private/worktree"}}\n',
    )
    worker_last_message = _write(
        config.transcripts_dir / integration.id / "worker" / "last-message.md",
        "worker result\n",
    )
    store.begin_iteration(
        integration.id,
        0,
        "Worker attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / integration.id / "prompt.md",
        worker_transcript_path=worker_transcript,
        worker_last_message_path=worker_last_message,
    )
    store.finish_iteration_worker(
        integration.id,
        0,
        _worker_result(config, worker_transcript, worker_last_message),
    )

    plan_transcript = _write(
        config.transcripts_dir / integration.id / "plan" / "codex.jsonl",
        '{"type":"item.completed","item":{"type":"agent_message","text":"plan result"}}\n',
    )
    plan_last_message = _write(
        config.transcripts_dir / integration.id / "plan" / "last-message.md",
        "plan result\n",
    )
    store.begin_plan_run(
        integration.id,
        1,
        prompt_path=config.prompts_dir / integration.id / "plan.md",
        transcript_path=plan_transcript,
        last_message_path=plan_last_message,
        model="planner-model",
        reasoning_effort="low",
    )

    commit_transcript = _write(
        config.transcripts_dir / integration.id / "commit-message" / "codex.jsonl",
        '{"type":"item.completed","item":{"type":"agent_message","text":"commit message"}}\n',
    )
    _write(
        config.transcripts_dir / integration.id / "commit-message" / "last-message.md",
        "commit message\n",
    )
    _write(
        config.logs_dir / integration.id / "git-push.txt",
        "push completed\n",
    )
    store.add_event(
        integration.id,
        "main.pushed",
        "c" * 40,
        {"path": "/home/contract-private/push.log"},
    )

    planner_id = "planner-task-20260713120000-a1b2c3d4"
    planner_transcript = _write(
        config.transcripts_dir / planner_id / "planner" / "codex.jsonl",
        '{"type":"item.completed","item":{"type":"agent_message","text":"planner result"}}\n',
    )
    planner_last_message = _write(
        config.transcripts_dir / planner_id / "planner" / "last-message.md",
        "planner result\n",
    )
    store.add_event(
        "daemon",
        "planner.finished",
        "planner finished",
        {
            "run_id": planner_id,
            "completed": True,
            "exit_code": 0,
            "accepted_count": 1,
            "proposed_count": 2,
            "consumed_item_ids": ["signal-contract-1"],
            "thread_id": "private-thread",
            "transcript_path": str(planner_transcript),
        },
    )
    assert not task_dir.exists()
    return integration, source


def _assert_utc_timestamps(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and (key == "generated_at" or key.endswith("_at")):
                assert item.endswith("Z"), (key, item)
                datetime.fromisoformat(item.replace("Z", "+00:00"))
            _assert_utc_timestamps(item)
    elif isinstance(value, list):
        for item in value:
            _assert_utc_timestamps(item)


def _assert_artifacts(value: Any) -> None:
    if isinstance(value, dict):
        if ARTIFACT_REQUIRED <= value.keys():
            assert value["mode"] == "redacted"
            assert value["availability"] == "available"
            assert isinstance(value["text"], str)
            assert isinstance(value["size_bytes"], int)
            assert isinstance(value["original_size_bytes"], (int, type(None)))
            assert isinstance(value["truncated"], bool)
            if value.get("sha256") is not None:
                assert re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
        for item in value.values():
            _assert_artifacts(item)
    elif isinstance(value, list):
        for item in value:
            _assert_artifacts(item)


@pytest.mark.parametrize(
    ("name", "status", "kind", "worker", "expected_state"),
    [
        ("empty", None, TaskKind.custom, WorkerKind.custom, "idle"),
        ("idle", TaskStatus.succeeded, TaskKind.custom, WorkerKind.custom, "idle"),
        ("active", TaskStatus.running, TaskKind.custom, WorkerKind.custom, "working"),
        ("failed", TaskStatus.failed, TaskKind.custom, WorkerKind.custom, "attention"),
        ("blocked", TaskStatus.blocked, TaskKind.custom, WorkerKind.custom, "attention"),
        (
            "integration",
            TaskStatus.integrating,
            TaskKind.integration,
            WorkerKind.integration_manager,
            "working",
        ),
    ],
)
def test_producer_snapshots_validate_for_each_public_state(
    config: StewardConfig,
    name: str,
    status: TaskStatus | None,
    kind: TaskKind,
    worker: WorkerKind,
    expected_state: str,
) -> None:
    config = _contract_config(config, publish=name not in {"empty", "failed"})
    store = TaskStore(config.db_path)
    runtime_state = (
        DaemonRuntimeState.active
        if status in {TaskStatus.running, TaskStatus.integrating}
        else DaemonRuntimeState.idle
    )
    runtime = DaemonRuntime(
        instance_id=f"steward-contract-{name}",
        started_at=FIXED_TIME - timedelta(minutes=5),
        heartbeat_at=FIXED_TIME,
        state=runtime_state,
        current_cycle_started_at=(FIXED_TIME - timedelta(seconds=10) if runtime_state == DaemonRuntimeState.active else None),
        current_cycle_reason=("contract-test" if runtime_state == DaemonRuntimeState.active else None),
    )
    if status is not None:
        _add_task(
            store,
            task_id=f"task-20260713120000-{name}",
            status=status,
            kind=kind,
            worker=worker,
        )
    publication = None if name == "empty" else _health(
        PublicMirrorPublishState.failed
        if name == "failed"
        else PublicMirrorPublishState.pending
        if name in {"active", "integration"}
        else PublicMirrorPublishState.published,
        category=(PublicMirrorFailureCategory.rsync_transfer if name == "failed" else None),
    )

    payload = public_mirror_payload(
        config,
        store,
        runtime=runtime,
        publication=publication,
    )

    validate_public_monitor(payload)
    assert payload["state"] == expected_state
    assert payload["runtime"]["state"] == runtime_state.value
    _assert_utc_timestamps(payload)


def test_rich_detail_and_public_records_are_schema_shaped_and_redacted(
    config: StewardConfig,
) -> None:
    config = _contract_config(config, publish=True)
    store = TaskStore(config.db_path)
    integration, source = _populate_detail_records(config, store)
    store.add_signal_items(
        [
            SignalItem(
                id="signal-contract-1",
                provider="contract",
                kind="finding",
                fingerprint="contract-fingerprint",
                title="API_KEY=contract-seeded-secret",
                summary="/home/contract-private/summary",
                links=[
                    {"label": "safe", "url": "https://github.com/minhuw/coquic/issues/1"},
                    {"label": "unsafe", "url": "https://evil.example.test/private"},
                ],
                payload={"prompt": "contract-seeded-secret", "token": "contract-seeded-secret"},
            )
        ]
    )
    store.add_signal_fetch_run(
        SignalFetchRun(
            id="signal-fetch-contract-1",
            provider="contract",
            status=SignalFetchStatus.error,
            item_count=1,
            new_item_count=1,
            summary="provider failed",
            error="Authorization: Bearer contract-seeded-secret",
        )
    )
    store.request_wakeup(
        "contract-test",
        {"path": "/home/contract-private/wakeup", "token": "contract-seeded-secret"},
    )

    payload = public_mirror_payload(
        config,
        store,
        runtime=DaemonRuntime(
            instance_id="steward-contract-rich",
            started_at=FIXED_TIME - timedelta(minutes=5),
            heartbeat_at=FIXED_TIME,
            state=DaemonRuntimeState.active,
            current_cycle_started_at=FIXED_TIME - timedelta(seconds=10),
            current_cycle_reason="contract-test",
        ),
        publication=_health(PublicMirrorPublishState.published),
    )
    detail = public_task_detail_payload(config, store, integration.id)

    validate_public_monitor(payload)
    assert payload["signals"]["items"][0]["links"] == [
        {"label": "safe", "url": "https://github.com/minhuw/coquic/issues/1"}
    ]
    assert payload["planner_runs"][0]["status"] == "succeeded"
    assert payload["integration"]["active"][0]["id"] == integration.id
    assert payload["publication"]["state"] == "published"
    assert payload["runtime"]["state"] == "active"
    assert detail["source_task"]["id"] == source.id
    assert detail["integration"]["is_integration_task"] is True
    assert detail["integration"]["runs"][0]["remote"]["commit"] == "c" * 40
    assert detail["attempts"][0]["worker"]["transcript"]["availability"] == "available"
    assert detail["plan_runs"][0]["planner"]["transcript"]["mode"] == "redacted"
    assert detail["attempts"][0]["validations"][0]["log"]["original_size_bytes"] > 0
    assert detail["artifacts"]["patch"]["truncated"] is False
    _assert_utc_timestamps(payload)
    _assert_utc_timestamps(detail)
    _assert_artifacts(payload)
    _assert_artifacts(detail)

    serialized = json.dumps({"payload": payload, "detail": detail}, sort_keys=True)
    for marker in PRIVATE_MARKERS:
        assert marker not in serialized


def _trajectory_record(
    *,
    sequence: int,
    status: str = "captured",
    patch: dict[str, object] | None = None,
    completed_at: str = "2026-07-13T12:00:01+00:00",
    tree: str = "a" * 40,
    result_tree: str | None = None,
) -> dict[str, object]:
    result_tree = tree if result_tree is None else result_tree
    record: dict[str, object] = {
        "tool_use_id": f"tool_{sequence}",
        "tool_name": "apply_patch",
        "session_id": "private-session",
        "turn_id": "private-turn",
        "start_sequence": sequence,
        "start_order": sequence,
        "start_monotonic_ns": sequence,
        "started_at": "2026-07-13T12:00:00+00:00",
        "base_tree": tree,
        "base_tree_id": tree,
        "gap_before": False,
        "overlap": False,
        "input": {"path": "inputs/private.json", "bytes": 20, "sha256": "b" * 64},
        "input_artifact": {"path": "inputs/private.json", "bytes": 20, "sha256": "b" * 64},
        "completion_sequence": sequence,
        "completion_order": sequence,
        "completed_at": completed_at,
        "duration_ms": 1,
        "result_tree": result_tree,
        "result_tree_id": result_tree,
        "status": status,
        "paths": ["include/coquic/core.h"] if status == "captured" else [],
        "patch": patch,
        "patch_path": patch["path"] if patch else None,
        "patch_size_bytes": patch["bytes"] if patch else 0,
        "patch_sha256": patch["sha256"] if patch else None,
        "response": {"path": "responses/private.json"},
        "response_artifact": {"path": "responses/private.json"},
        "error_category": None,
    }
    return record


def _write_trajectory_fixture(
    config: StewardConfig,
    task_id: str,
    *,
    records: list[dict[str, object]],
    retry: bool = False,
    tree: str = "a" * 40,
    final_tree: str | None = None,
) -> Path:
    final_tree = tree if final_tree is None else final_tree
    transcript = _write(
        config.transcripts_dir / task_id / "worker" / "codex.jsonl", "worker\n"
    )
    _write(config.transcripts_dir / task_id / "worker" / "last-message.md", "done\n")
    run_dir = transcript.parent / ("tool-changes.retry-1" if retry else "tool-changes")
    run_dir.mkdir(parents=True, exist_ok=True)
    captured = sum(item["status"] == "captured" for item in records)
    empty = sum(item["status"] == "empty" for item in records)
    failed = sum(item["status"] == "failed" for item in records)
    _write(
        run_dir / "summary.json",
        json.dumps(
            {
                "schema_version": 1,
                "state": "complete",
                "completeness": "complete",
                "discovered": len(records),
                "captured": captured,
                "empty": empty,
                "failed": failed,
                "incomplete": 0,
                "gaps": 0,
                "overlaps": 0,
                "omitted": 0,
                "reasons": [],
                "reason_categories": [],
                "run_start_tree": tree,
                "final_tree": final_tree,
                "replayed_tree": final_tree,
                "run_start_tree_id": tree,
                "final_tree_id": final_tree,
                "replayed_tree_id": final_tree,
            }
        ),
    )
    _write(
        run_dir / "manifest.jsonl",
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in records),
    )
    return transcript


def test_worker_change_trajectory_is_bounded_redacted_and_additive(
    config: StewardConfig,
) -> None:
    config = _contract_config(config)
    store = TaskStore(config.db_path)
    task = _add_task(
        store,
        task_id="task-20260713120010-trajectory",
        status=TaskStatus.succeeded,
    )
    patch_text = (
        "diff --git a/include/coquic/core.h b/include/coquic/core.h\n"
        "+safe_call()\n"
        '+endpoint = "https://private.example.test/v1"\n'
        '+credential = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"\n'
        '+prompt = "private prompt text that must not publish"\n'
        '+connect("ssh://deploy:topsecret@example.test/repository")\n'
        '+authenticate("glpat-0123456789abcdefghijklmnop")\n'
        '+load_key(r"C:\\Users\\alice\\private\\key.pem")\n'
    )
    patch_path = config.transcripts_dir / task.id / "worker" / "tool-changes" / "patches" / "1-tool_1.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(patch_text, encoding="utf-8")
    patch_meta = {
        "path": "patches/1-tool_1.patch",
        "bytes": len(patch_text.encode()),
        "sha256": sha256(patch_text.encode()).hexdigest(),
    }
    result_tree = "b" * 40
    record = _trajectory_record(
        sequence=1,
        patch=patch_meta,
        result_tree=result_tree,
    )
    transcript = _write_trajectory_fixture(
        config,
        task.id,
        records=[record],
        final_tree=result_tree,
    )
    # The fixture writer uses the same transcript path and run directory.
    store.begin_iteration(
        task.id,
        0,
        "Worker attempt",
        worker_name="worker",
        worker_prompt_path=None,
        worker_transcript_path=transcript,
        worker_last_message_path=transcript.with_name("last-message.md"),
    )
    store.finish_iteration_worker(task.id, 0, _worker_result(config, transcript, transcript.with_name("last-message.md")))

    detail = public_task_detail_payload(config, store, task.id)
    trajectory = detail["attempts"][0]["worker"]["change_trajectory"]
    assert trajectory["availability"] == "available"
    assert trajectory["completeness"] == "complete"
    assert trajectory["published_count"] == 1
    assert trajectory["changes"][0]["paths"] == ["include/coquic/core.h"]
    assert trajectory["changes"][0]["patch"]["availability"] == "available"
    public_patch = trajectory["changes"][0]["patch"]["text"]
    assert "safe_call()" in public_patch
    assert "https://" not in public_patch
    assert "ssh://" not in public_patch
    assert "topsecret" not in public_patch
    assert "ghp_" not in public_patch
    assert "glpat-" not in public_patch
    assert r"C:\Users" not in public_patch
    assert r"C:\Users\alice\private\key.pem" not in public_patch
    assert "private prompt" not in public_patch
    assert "private-session" not in json.dumps(trajectory)
    assert "inputs/private.json" not in json.dumps(trajectory)
    assert "responses/private.json" not in json.dumps(trajectory)


def test_worker_change_trajectory_truncates_records_without_upgrading_completeness(
    config: StewardConfig,
) -> None:
    config = _contract_config(config)
    store = TaskStore(config.db_path)
    task = _add_task(
        store,
        task_id="task-20260713120011-trajectory",
        status=TaskStatus.succeeded,
    )
    records = [_trajectory_record(sequence=index, status="empty") for index in range(1, 102)]
    transcript = _write_trajectory_fixture(config, task.id, records=records)
    store.begin_iteration(
        task.id,
        0,
        "Worker attempt",
        worker_name="worker",
        worker_prompt_path=None,
        worker_transcript_path=transcript,
        worker_last_message_path=transcript.with_name("last-message.md"),
    )
    store.finish_iteration_worker(task.id, 0, _worker_result(config, transcript, transcript.with_name("last-message.md")))

    trajectory = public_task_detail_payload(config, store, task.id)["attempts"][0]["worker"]["change_trajectory"]
    assert trajectory["published_count"] == 100
    assert trajectory["omitted_count"] == 1
    assert trajectory["truncated"] is True
    assert trajectory["completeness"] == "partial"
    assert [item["sequence"] for item in trajectory["changes"]] == list(range(1, 101))


def test_worker_change_trajectory_restores_retry_records_chronologically(
    config: StewardConfig,
) -> None:
    config = _contract_config(config)
    store = TaskStore(config.db_path)
    task = _add_task(
        store,
        task_id="task-20260713120012-trajectory",
        status=TaskStatus.succeeded,
    )
    _write_trajectory_fixture(
        config,
        task.id,
        records=[
            _trajectory_record(
                sequence=1,
                status="empty",
                completed_at="2026-07-13T12:00:01+00:00",
            )
        ],
        retry=True,
    )
    transcript = _write_trajectory_fixture(
        config,
        task.id,
        records=[
            _trajectory_record(
                sequence=1,
                status="empty",
                completed_at="2026-07-13T12:00:02+00:00",
            )
        ],
    )
    store.begin_iteration(
        task.id,
        0,
        "Worker attempt",
        worker_name="worker",
        worker_prompt_path=None,
        worker_transcript_path=transcript,
        worker_last_message_path=transcript.with_name("last-message.md"),
    )
    store.finish_iteration_worker(
        task.id,
        0,
        _worker_result(config, transcript, transcript.with_name("last-message.md")),
    )

    trajectory = public_task_detail_payload(config, store, task.id)["attempts"][0]["worker"]["change_trajectory"]
    assert trajectory["discovered_count"] == 2
    assert trajectory["published_count"] == 2
    assert [item["tool_call_id"] for item in trajectory["changes"]] == ["tool_1", "tool_1"]
    assert [item["sequence"] for item in trajectory["changes"]] == [1, 2]


def test_worker_change_trajectory_rejects_retry_tree_discontinuity(
    config: StewardConfig,
) -> None:
    config = _contract_config(config)
    task_id = "task-20260713120013-trajectory"
    retry_tree = "a" * 40
    final_tree = "b" * 40
    _write_trajectory_fixture(
        config,
        task_id,
        records=[_trajectory_record(sequence=1, status="empty", tree=retry_tree)],
        retry=True,
        tree=retry_tree,
    )
    transcript = _write_trajectory_fixture(
        config,
        task_id,
        records=[_trajectory_record(sequence=1, status="empty", tree=final_tree)],
        tree=final_tree,
    )

    trajectory = _public_change_trajectory(config, transcript)

    assert trajectory["availability"] == "unavailable"
    assert trajectory["completeness"] == "unavailable"
    assert trajectory["changes"] == []


@pytest.mark.parametrize(
    ("status", "result_tree", "with_patch", "paths"),
    [
        ("empty", "b" * 40, False, []),
        ("captured", "a" * 40, True, ["include/coquic/core.h"]),
        ("empty", "a" * 40, False, ["include/coquic/core.h"]),
    ],
)
def test_worker_change_trajectory_rejects_inconsistent_status_tree_evidence(
    config: StewardConfig,
    status: str,
    result_tree: str,
    with_patch: bool,
    paths: list[str],
) -> None:
    config = _contract_config(config)
    task_id = f"task-20260713120014-{status}-{int(with_patch)}-{len(paths)}"
    patch = None
    if with_patch:
        patch_text = "+safe_call()\n"
        patch_path = (
            config.transcripts_dir
            / task_id
            / "worker"
            / "tool-changes"
            / "patches"
            / "1-tool_1.patch"
        )
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text(patch_text, encoding="utf-8")
        patch = {
            "path": "patches/1-tool_1.patch",
            "bytes": len(patch_text.encode()),
            "sha256": sha256(patch_text.encode()).hexdigest(),
        }
    record = _trajectory_record(
        sequence=1,
        status=status,
        patch=patch,
        result_tree=result_tree,
    )
    record["paths"] = paths
    transcript = _write_trajectory_fixture(
        config,
        task_id,
        records=[record],
        final_tree=result_tree,
    )

    trajectory = _public_change_trajectory(config, transcript)

    assert trajectory["availability"] == "unavailable"
    assert trajectory["completeness"] == "unavailable"
    assert trajectory["changes"] == []


@pytest.mark.parametrize("line_bytes", [32 * 1024, MIRROR_TRAJECTORY_PATCH_BYTES])
def test_trajectory_patch_redaction_has_bounded_runtime(
    config: StewardConfig,
    line_bytes: int,
) -> None:
    data = ("+" + "x" * (line_bytes - 2) + "\n").encode()

    started = monotonic()
    projected = _trajectory_redacted_patch(config, data)
    elapsed = monotonic() - started

    assert len(data) == line_bytes
    assert projected == data.decode()
    assert elapsed < 1.0


def test_worker_change_trajectory_counts_per_patch_truncation_as_omitted(
    config: StewardConfig,
) -> None:
    config = _contract_config(config)
    task_id = "task-20260713120015-per-patch-budget"
    patch_text = "+safe\n" * 25_000 + "+" * 81
    patch_path = (
        config.transcripts_dir
        / task_id
        / "worker"
        / "tool-changes"
        / "patches"
        / "1-tool_1.patch"
    )
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(patch_text, encoding="utf-8")
    patch = {
        "path": "patches/1-tool_1.patch",
        "bytes": len(patch_text.encode()),
        "sha256": sha256(patch_text.encode()).hexdigest(),
    }
    final_tree = "b" * 40
    record = _trajectory_record(
        sequence=1,
        patch=patch,
        result_tree=final_tree,
    )
    transcript = _write_trajectory_fixture(
        config,
        task_id,
        records=[record],
        final_tree=final_tree,
    )

    trajectory = _public_change_trajectory(config, transcript)

    public_patch = trajectory["changes"][0]["patch"]
    assert len(patch_text.encode()) == 150_081
    assert public_patch["original_size_bytes"] == len(patch_text.encode())
    assert public_patch["size_bytes"] <= MIRROR_TRAJECTORY_PATCH_BYTES
    assert public_patch["truncated"] is True
    assert trajectory["omitted_count"] == 1
    assert trajectory["truncated"] is True
    assert trajectory["completeness"] == "partial"


def test_worker_change_trajectory_counts_aggregate_patch_omissions_exactly(
    config: StewardConfig,
) -> None:
    config = _contract_config(config)
    task_id = "task-20260713120016-aggregate-budget"
    patch_text = "+safe\n" * 20_000
    trees = [f"{index:040x}" for index in range(6)]
    records = []
    for sequence in range(1, 6):
        patch_path = (
            config.transcripts_dir
            / task_id
            / "worker"
            / "tool-changes"
            / "patches"
            / f"{sequence}-tool_{sequence}.patch"
        )
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text(patch_text, encoding="utf-8")
        patch = {
            "path": f"patches/{sequence}-tool_{sequence}.patch",
            "bytes": len(patch_text.encode()),
            "sha256": sha256(patch_text.encode()).hexdigest(),
        }
        records.append(
            _trajectory_record(
                sequence=sequence,
                patch=patch,
                tree=trees[sequence - 1],
                result_tree=trees[sequence],
            )
        )
    transcript = _write_trajectory_fixture(
        config,
        task_id,
        records=records,
        tree=trees[0],
        final_tree=trees[-1],
    )

    trajectory = _public_change_trajectory(config, transcript)

    patches = [change["patch"] for change in trajectory["changes"]]
    assert sum(patch["size_bytes"] for patch in patches) <= (
        MIRROR_TRAJECTORY_AGGREGATE_PATCH_BYTES
    )
    assert [patch["truncated"] for patch in patches] == [False] * 4 + [True]
    assert all(patch["original_size_bytes"] == len(patch_text.encode()) for patch in patches)
    assert trajectory["published_count"] == 5
    assert trajectory["omitted_count"] == 1
    assert trajectory["truncated"] is True
    assert trajectory["completeness"] == "partial"


def _resolve_schema(root: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema:
        value: Any = root
        for part in str(schema["$ref"])[2:].split("/"):
            value = value[part]
        schema = value
    return schema


def _required_paths(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: tuple[str | int, ...] = (),
) -> list[tuple[str | int, ...]]:
    schema = _resolve_schema(root, schema)
    if "anyOf" in schema:
        branches = schema["anyOf"]
        selected = next(
            branch
            for branch in branches
            if (value is None and branch.get("type") == "null")
            or (value is not None and branch.get("type") != "null")
        )
        return _required_paths(value, selected, root, path)
    if isinstance(value, list):
        item_schema = schema.get("items")
        if not isinstance(item_schema, dict):
            return []
        paths: list[tuple[str | int, ...]] = []
        for index, item in enumerate(value):
            paths.extend(_required_paths(item, item_schema, root, path + (index,)))
        return paths
    if not isinstance(value, dict):
        return []
    properties = schema.get("properties", {})
    paths = []
    for name in schema.get("required", []):
        child_path = path + (name,)
        paths.append(child_path)
        child_schema = properties.get(name)
        if isinstance(child_schema, dict) and name in value:
            paths.extend(_required_paths(value[name], child_schema, root, child_path))
    return paths


def _remove_path(value: Any, path: tuple[str | int, ...]) -> None:
    parent = value
    for component in path[:-1]:
        parent = parent[component]
    del parent[path[-1]]


def test_every_required_field_rejects_a_missing_producer_contract_value() -> None:
    document = json.loads((FIXTURE_DIR / "integration.json").read_text(encoding="utf-8"))
    schema = load_schema()
    paths = _required_paths(document, schema, schema)
    assert len(paths) >= 80

    for path in paths:
        mutated = copy.deepcopy(document)
        _remove_path(mutated, path)
        with pytest.raises(SchemaValidationError):
            validate_public_monitor(mutated)


def test_heartbeat_only_changes_digest_and_publication_health_transitions(
    config: StewardConfig,
) -> None:
    config = _contract_config(config, publish=True)
    store = TaskStore(config.db_path)
    runtime = DaemonRuntime(
        instance_id="steward-contract-heartbeat",
        started_at=FIXED_TIME - timedelta(minutes=5),
        heartbeat_at=FIXED_TIME,
        state=DaemonRuntimeState.idle,
    )
    before = public_mirror_digest(config, store, runtime=runtime)
    pending = public_mirror_payload(
        config,
        store,
        runtime=runtime,
        publication=PublicMirrorHealth(
            state=PublicMirrorPublishState.pending,
            generated_at=FIXED_TIME,
        ),
    )
    runtime.heartbeat_at += timedelta(seconds=30)
    after = public_mirror_digest(config, store, runtime=runtime)
    failed = public_mirror_payload(
        config,
        store,
        runtime=runtime,
        publication=_health(
            PublicMirrorPublishState.failed,
            category=PublicMirrorFailureCategory.timeout,
        ),
    )
    recovered = public_mirror_payload(
        config,
        store,
        runtime=runtime,
        publication=_health(PublicMirrorPublishState.published),
    )

    assert before != after
    assert pending["publication"]["state"] == "pending"
    assert failed["publication"]["state"] == "failed"
    assert failed["publication"]["last_failure_category"] == "timeout"
    assert recovered["publication"]["state"] == "published"
    assert recovered["publication"]["retry_count"] == 0
    for payload in (pending, failed, recovered):
        validate_public_monitor(payload)


def test_golden_fixtures_are_deterministic_and_private_free() -> None:
    assert {path.name for path in FIXTURE_DIR.glob("*.json")} == EXPECTED_FIXTURES
    for fixture in sorted(FIXTURE_DIR.glob("*.json")):
        document = json.loads(fixture.read_text(encoding="utf-8"))
        validate_public_monitor(document)
        assert document["generated_at"] == "2026-07-13T12:00:00Z"
        compact = json.dumps(document, sort_keys=True, separators=(",", ":"))
        assert json.loads(compact) == document
        for marker in PRIVATE_MARKERS:
            assert marker not in compact

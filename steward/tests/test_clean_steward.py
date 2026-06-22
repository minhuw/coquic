from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from coquic_steward.core.config import StewardConfig, StewardLimits, load_config
from coquic_steward.core.lifecycle import InvalidTaskTransition
from coquic_steward.core.models import (
    IntegrationMode,
    Priority,
    Risk,
    SignalItem,
    SignalItemStatus,
    SignalMessage,
    SignalMessageStatus,
    TaskKind,
    TaskSpec,
    TaskStatus,
    ValidationResult,
    WorkerKind,
    utc_now,
)
from coquic_steward.storage import TaskStore
from coquic_steward.storage.schema import (
    EventRow,
    TaskIterationRow,
    TaskRow,
    ValidationRow,
)

def test_config_defaults_from_repo(repo: Path, coquic_home: Path) -> None:
    config = load_config(repo_root=repo)
    assert config.repo_root == repo
    assert config.steward_home == coquic_home / "steward"
    assert config.db_path.parent.parent == coquic_home / "steward" / "repos"
    assert config.db_path.name == "steward.sqlite"
    assert config.legacy_json_path == config.state_dir / "steward.json"
    assert config.worktrees_dir == config.state_dir / "worktrees"
    assert config.transcripts_dir == config.state_dir / "transcripts"
    assert config.integration_mode == "local-only"
    assert config.local_only is False
    assert config.enabled_signals == ("github-actions", "code-scanning", "codacy")


def test_config_selects_enabled_signals(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.signals]
enabled = ["codacy"]
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.enabled_signals == ("codacy",)


def test_config_reads_review_timeout_limit(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.limits]
review_timeout_minutes = 7
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.limits.review_timeout_minutes == 7


def test_config_reads_local_only(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"
integration_mode = "push-main"
local_only = false
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.integration_mode == IntegrationMode.push_main.value
    assert config.local_only is False


def test_config_resolves_codex_bin_from_path(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    config_path = tmp_path / "steward.toml"
    config_path.write_text(
        """
[steward]
codex_bin = "codex"
github_repository = "minhuw/coquic"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.codex_bin == str(fake)


def test_config_reads_only_global_file_by_default(
    repo: Path, coquic_home: Path
) -> None:
    global_config = coquic_home / "steward.toml"
    global_config.parent.mkdir(parents=True, exist_ok=True)
    global_config.write_text(
        """
[steward]
codex_sandbox = "read-only"
github_repository = "minhuw/global"

[steward.signals]
enabled = ["codacy"]
""",
        encoding="utf-8",
    )
    repo_config = repo / "steward" / "steward.toml"
    repo_config.parent.mkdir(parents=True, exist_ok=True)
    repo_config.write_text(
        """
[steward]
github_repository = "minhuw/coquic"
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo)

    assert config.codex_sandbox == "read-only"
    assert config.github_repository == "minhuw/global"
    assert config.enabled_signals == ("codacy",)


def test_store_dedupes_active_tasks(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    spec = TaskSpec(
        kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P"
    )

    first, created = store.add_task(spec, dedupe_key="same")
    second, duplicate_created = store.add_task(spec, dedupe_key="same")

    assert created
    assert not duplicate_created
    assert first.id == second.id
    assert store.get(first.id).status == TaskStatus.queued


def test_store_recovers_stale_active_tasks(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    spec = TaskSpec(
        kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P"
    )
    task, _ = store.add_task(spec, dedupe_key="same")
    store.update_status(task.id, TaskStatus.running, "started")
    make_task_stale(store, task.id)

    recovered = store.recover_stale_active_tasks(stale_after_minutes=10)

    assert recovered == [task.id]
    recovered_task = store.get(task.id)
    assert recovered_task.status == TaskStatus.failed
    assert "stale active task recovered" in recovered_task.summary
    replacement, created = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P"),
        dedupe_key="same",
    )
    assert created
    assert replacement.id != task.id


def test_store_touches_only_active_tasks(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.update_status(task.id, TaskStatus.running, "started")
    make_task_stale(store, task.id)

    assert store.touch_active_task(task.id)
    assert store.get(task.id).updated_at > utc_now() - timedelta(minutes=1)

    store.update_status(task.id, TaskStatus.failed, "failed")
    make_task_stale(store, task.id)
    assert not store.touch_active_task(task.id)
    assert store.get(task.id).updated_at < utc_now() - timedelta(minutes=10)


def test_store_rejects_invalid_task_status_transition(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    with pytest.raises(InvalidTaskTransition):
        store.start_review(task.id, "review started")

    assert store.get(task.id).status == TaskStatus.queued


def test_store_allows_integration_conflict_to_return_to_worker(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.start_worker(task.id, "worker started")
    store.start_integration(task.id, "integration queued")

    store.start_worker(task.id, "addressing integration conflict revision 1")

    saved = store.get(task.id)
    assert saved.status == TaskStatus.running
    assert saved.summary == "addressing integration conflict revision 1"


def test_store_save_does_not_overwrite_lifecycle_state(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    stale = store.get(task.id)
    store.start_worker(task.id, "worker started")
    stale.summary = "stale queued object"
    stale.worktree_path = config.worktrees_dir / "stale"

    store.save(stale)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.running
    assert saved.summary == "worker started"
    assert saved.worktree_path == config.worktrees_dir / "stale"


def test_store_dispatches_integration_tasks_first(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    normal, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="normal",
            prompt="normal",
            priority=Priority.urgent,
        )
    )
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="integrate",
            prompt="integrate",
            priority=Priority.low,
        )
    )

    queued = store.queued_tasks()

    assert [task.id for task in queued] == [integration.id, normal.id]


def test_store_dedupes_signal_messages(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)

    first, first_created = store.add_signal_message(
        SignalMessage(
            provider="codacy",
            kind="codacy-open",
            fingerprint="codacy:open:2",
            title="Open Codacy findings",
            summary="Codacy issuesCount=2",
            evidence_id="codacy:open",
            payload={"path": str(config.logs_dir / "codacy.json")},
        )
    )
    second, second_created = store.add_signal_message(
        SignalMessage(
            provider="codacy",
            kind="codacy-open",
            fingerprint="codacy:open:2",
            title="Open Codacy findings",
            summary="Codacy issuesCount=2",
            evidence_id="codacy:open",
        )
    )

    assert first_created is True
    assert second_created is False
    assert second.id == first.id
    pending = store.pending_signal_messages()
    assert [message.id for message in pending] == [first.id]
    assert pending[0].payload["path"] == str(config.logs_dir / "codacy.json")


def test_store_consumes_signal_messages_after_planner_acceptance(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    message, _ = store.add_signal_message(
        SignalMessage(
            provider="code-scanning",
            kind="codeql-open",
            fingerprint="codeql:open",
            title="Open CodeQL findings",
            evidence_id="codeql:open",
        )
    )

    consumed = store.consume_signal_messages([message.id], planner_run_id="planner-1")

    assert consumed == 1
    saved = store.list_signal_messages()[0]
    assert saved.status == SignalMessageStatus.consumed
    assert saved.planner_run_id == "planner-1"
    assert saved.consumed_at is not None


def test_store_allows_fresh_signal_after_consumption(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    first, _ = store.add_signal_message(
        SignalMessage(
            provider="code-scanning",
            kind="codeql-open",
            fingerprint="codeql:open",
            title="Open CodeQL findings",
            evidence_id="codeql:open",
        )
    )
    store.consume_signal_messages([first.id], planner_run_id="planner-1")

    second, created = store.add_signal_message(
        SignalMessage(
            provider="code-scanning",
            kind="codeql-open",
            fingerprint="codeql:open",
            title="Open CodeQL findings",
            evidence_id="codeql:open",
        )
    )

    assert created is True
    assert second.id != first.id
    assert len(store.list_signal_messages()) == 2


def test_store_tracks_signal_items_independently(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    item, created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy-issue",
            fingerprint="wi-codacy-1",
            title="SC2034 in scripts/fuzz-targets.sh:9",
            evidence_id="codacy:open",
            payload={
                "id": "wi-codacy-1",
                "provider": "codacy",
                "kind": "codacy-issue",
                "rule_id": "shellcheck_SC2034",
                "file": "scripts/fuzz-targets.sh",
                "line": 9,
            },
        )
    )
    duplicate, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy-issue",
            fingerprint="wi-codacy-1",
            title="SC2034 in scripts/fuzz-targets.sh:9",
            evidence_id="codacy:open",
        )
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate.id == item.id
    assert [pending.id for pending in store.pending_signal_items()] == ["wi-codacy-1"]


def test_store_marks_signal_items_planned(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    store.add_signal_item(
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="codeql-alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
            evidence_id="codeql:open",
        )
    )

    marked = store.mark_signal_items_planned(
        ["wi-codeql-1"], planner_run_id="planner-1", task_id="task-1"
    )

    assert marked == 1
    item = store.list_signal_items()[0]
    assert item.status == SignalItemStatus.planned
    assert item.planner_run_id == "planner-1"
    assert item.planned_task_id == "task-1"
    assert item.planned_at is not None
    assert store.pending_signal_items() == []


def test_store_supersedes_consumed_signal_items_without_tasks(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    store.add_signal_item(
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="codeql-alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
            evidence_id="codeql:open",
        )
    )

    superseded = store.supersede_signal_items(
        ["wi-codeql-1"], planner_run_id="planner-1"
    )

    assert superseded == 1
    item = store.list_signal_items()[0]
    assert item.status == SignalItemStatus.superseded
    assert item.planner_run_id == "planner-1"
    assert store.pending_signal_items() == []


def test_store_treats_unfinished_review_revision_as_worker_active(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="R", prompt="R")
    )
    store.start_worker(task.id, "worker started")
    store.start_review(task.id, "review started")
    store.add_event(task.id, "review.finished", "{}")
    store.add_event(task.id, "worker.revision_requested", "needs revision")
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.status = TaskStatus.reviewing.value
    make_task_stale(store, task.id, minutes=30)

    recovered = store.recover_stale_active_tasks(
        stale_after_minutes=125,
        status_stale_after_minutes={TaskStatus.reviewing.value: 25},
    )

    assert recovered == []
    assert store.get(task.id).status == TaskStatus.reviewing


def test_store_marks_task_running_when_revision_iteration_begins(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="R", prompt="R")
    )
    store.start_worker(task.id, "worker started")
    store.start_review(task.id, "review started")

    store.begin_iteration(
        task.id,
        1,
        "Review revision 1",
        worker_name="worker-revision-1",
        worker_prompt_path=config.prompts_dir / task.id / "worker-revision-1.md",
        worker_transcript_path=config.transcripts_dir
        / task.id
        / "worker-revision-1"
        / "codex.jsonl",
        worker_last_message_path=config.transcripts_dir
        / task.id
        / "worker-revision-1"
        / "last-message.md",
        running_summary="addressing review revision 1",
    )

    saved = store.get(task.id)
    events = store.events(task.id)
    assert saved.status == TaskStatus.running
    assert saved.summary == "addressing review revision 1"
    assert events[-1].kind == "task.status"
    assert events[-1].message == "running"
    assert events[-1].data["source"] == "begin_iteration"


def test_store_recovers_unfinished_review_revision_with_worker_timeout(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="R", prompt="R")
    )
    store.start_worker(task.id, "worker started")
    store.start_review(task.id, "review started")
    store.add_event(task.id, "review.finished", "{}")
    store.add_event(task.id, "worker.revision_requested", "needs revision")
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.status = TaskStatus.reviewing.value
    make_task_stale(store, task.id, minutes=130)

    recovered = store.recover_stale_active_tasks(
        stale_after_minutes=125,
        status_stale_after_minutes={TaskStatus.reviewing.value: 25},
    )

    assert recovered == [task.id]
    assert store.get(task.id).status == TaskStatus.failed
    recovered_event = next(
        event for event in store.events(task.id) if event.kind == "task.recovered_stale"
    )
    assert recovered_event.data["previous_status"] == "reviewing"
    assert recovered_event.data["effective_status"] == "running"
    assert recovered_event.data["stale_after_minutes"] == 125
def test_store_records_in_progress_iteration_review(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worker = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    last = worker.parent / "last-message.md"
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=worker,
        worker_last_message_path=last,
    )

    store.start_iteration_review(
        task.id,
        0,
        reviewer_name="reviewer-0",
        reviewer_prompt_path=config.prompts_dir / task.id / "reviewer-0.md",
        reviewer_transcript_path=config.transcripts_dir
        / task.id
        / "reviewer-0"
        / "codex.jsonl",
        reviewer_last_message_path=config.transcripts_dir
        / task.id
        / "reviewer-0"
        / "last-message.md",
        review_run=0,
    )

    iteration = store.get_iteration(task.id, 0)
    assert iteration.reviewer_name == "reviewer-0"
    assert iteration.reviewer_completed is False
    assert (
        iteration.reviewer_transcript_path
        == config.transcripts_dir / task.id / "reviewer-0" / "codex.jsonl"
    )
def test_store_persists_tasks_in_sqlite(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.ci,
            worker=WorkerKind.ci_doctor,
            title="CI",
            prompt="fix",
            priority=Priority.high,
            risk=Risk.medium,
        )
    )

    reopened = TaskStore(config.db_path)
    saved = reopened.get(task.id)
    assert saved.spec.title == "CI"
    assert reopened.count_events("task.created") == 1


def test_store_persists_state_artifact_paths_relative(config: StewardConfig) -> None:
    from coquic_steward.core.models import ValidationResult

    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.worktrees_dir / task.id
    task.transcript_path = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    task.last_message_path = (
        config.transcripts_dir / task.id / "worker" / "last-message.md"
    )
    task.patch_path = config.patches_dir / task.id / "iteration-0.patch"
    task.spec.metadata = {
        "source_patch_path": str(task.patch_path),
        "source_worktree_path": str(task.worktree_path),
        "note": "patches/looks-like-text",
    }
    validation_log = config.logs_dir / task.id / "iteration-0" / "validation.txt"
    task.validations.append(
        ValidationResult(
            command=["fake"],
            cwd=config.repo_root,
            passed=True,
            exit_code=0,
            output_path=validation_log,
        )
    )
    store.save(task)
    store.add_event(
        task.id,
        "artifact.ready",
        str(task.patch_path),
        {
            "patch_path": str(task.patch_path),
            "failed": [{"output_path": str(validation_log)}],
            "note": "patches/looks-like-text",
        },
    )
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=task.transcript_path,
        worker_last_message_path=task.last_message_path,
    )
    store.record_iteration_patch(task.id, 0, task.patch_path)

    with Session(store.engine) as session:
        row = session.get(TaskRow, task.id)
        assert row is not None
        validation = session.query(ValidationRow).filter_by(task_id=task.id).one()
        iteration = session.query(TaskIterationRow).filter_by(task_id=task.id).one()
        assert row.worktree_path == f"worktrees/{task.id}"
        assert row.transcript_path == f"transcripts/{task.id}/worker/codex.jsonl"
        assert row.last_message_path == f"transcripts/{task.id}/worker/last-message.md"
        assert row.patch_path == f"patches/{task.id}/iteration-0.patch"
        assert json.loads(row.metadata_json) == {
            "note": "patches/looks-like-text",
            "source_patch_path": f"patches/{task.id}/iteration-0.patch",
            "source_worktree_path": f"worktrees/{task.id}",
        }
        assert validation.output_path == f"logs/{task.id}/iteration-0/validation.txt"
        assert validation.cwd == str(config.repo_root)
        assert iteration.worker_prompt_path == f"prompts/{task.id}/worker.md"
        assert iteration.worker_transcript_path == f"transcripts/{task.id}/worker/codex.jsonl"
        assert iteration.worker_last_message_path == f"transcripts/{task.id}/worker/last-message.md"
        assert iteration.patch_path == f"patches/{task.id}/iteration-0.patch"
        event = session.query(EventRow).filter_by(kind="artifact.ready").one()
        assert event.message == f"patches/{task.id}/iteration-0.patch"
        assert json.loads(event.data_json) == {
            "failed": [{"output_path": f"logs/{task.id}/iteration-0/validation.txt"}],
            "note": "patches/looks-like-text",
            "patch_path": f"patches/{task.id}/iteration-0.patch",
        }

    reopened = TaskStore(config.db_path)
    saved = reopened.get(task.id)
    iteration = reopened.get_iteration(task.id, 0)
    assert saved.worktree_path == config.worktrees_dir / task.id
    assert saved.transcript_path == config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    assert saved.spec.metadata["source_patch_path"] == str(task.patch_path)
    assert saved.spec.metadata["source_worktree_path"] == str(task.worktree_path)
    assert saved.spec.metadata["note"] == "patches/looks-like-text"
    assert saved.validations[0].output_path == validation_log
    assert saved.validations[0].cwd == config.repo_root
    event_data = next(
        event.data for event in reopened.events(task.id) if event.kind == "artifact.ready"
    )
    event = next(event for event in reopened.events(task.id) if event.kind == "artifact.ready")
    assert event.message == str(task.patch_path)
    assert event_data["patch_path"] == str(task.patch_path)
    assert event_data["failed"][0]["output_path"] == str(validation_log)
    assert event_data["note"] == "patches/looks-like-text"
    assert iteration.worker_prompt_path == config.prompts_dir / task.id / "worker.md"
    assert iteration.patch_path == config.patches_dir / task.id / "iteration-0.patch"


def test_store_leaves_external_paths_absolute(config: StewardConfig, tmp_path: Path) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    external = tmp_path / "external-worktree"
    task.worktree_path = external

    store.save(task)

    with Session(store.engine) as session:
        row = session.get(TaskRow, task.id)
        assert row is not None
        assert row.worktree_path == str(external)
    assert TaskStore(config.db_path).get(task.id).worktree_path == external


def test_store_migrates_existing_absolute_state_paths(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    absolute_patch = config.patches_dir / task.id / "iteration-0.patch"
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.patch_path = str(absolute_patch)
        row.metadata_json = json.dumps(
            {
                "source_patch_path": str(absolute_patch),
                "source_worktree_path": str(config.worktrees_dir / task.id),
            }
        )
        session.add(
            TaskIterationRow(
                task_id=task.id,
                iteration=0,
                label="Initial attempt",
                worker_name="worker",
                worker_prompt_path=str(config.prompts_dir / task.id / "worker.md"),
                worker_transcript_path=str(
                    config.transcripts_dir / task.id / "worker" / "codex.jsonl"
                ),
                worker_last_message_path=str(
                    config.transcripts_dir / task.id / "worker" / "last-message.md"
                ),
                patch_path=str(absolute_patch),
                started_at=utc_now().isoformat(),
                updated_at=utc_now().isoformat(),
            )
        )
        session.add(
            ValidationRow(
                task_id=task.id,
                iteration=0,
                position=0,
                command_json="[]",
                cwd=str(config.worktrees_dir / task.id),
                passed=True,
                exit_code=0,
                output_path=str(config.logs_dir / task.id / "validation.txt"),
                summary="",
                started_at=utc_now().isoformat(),
                completed_at=utc_now().isoformat(),
            )
        )
        session.add(
            EventRow(
                task_id=task.id,
                kind="artifact.ready",
                message=str(absolute_patch),
                created_at=utc_now().isoformat(),
                data_json=json.dumps({"patch_path": str(absolute_patch)}),
            )
        )

    reopened = TaskStore(config.db_path)

    with Session(reopened.engine) as session:
        row = session.get(TaskRow, task.id)
        iteration = session.query(TaskIterationRow).filter_by(task_id=task.id).one()
        validation = session.query(ValidationRow).filter_by(task_id=task.id).one()
        event = session.query(EventRow).filter_by(task_id=task.id, kind="artifact.ready").one()
        assert row is not None
        assert row.patch_path == f"patches/{task.id}/iteration-0.patch"
        assert json.loads(row.metadata_json) == {
            "source_patch_path": f"patches/{task.id}/iteration-0.patch",
            "source_worktree_path": f"worktrees/{task.id}",
        }
        assert iteration.worker_prompt_path == f"prompts/{task.id}/worker.md"
        assert iteration.patch_path == f"patches/{task.id}/iteration-0.patch"
        assert validation.cwd == f"worktrees/{task.id}"
        assert validation.output_path == f"logs/{task.id}/validation.txt"
        assert event.message == f"patches/{task.id}/iteration-0.patch"
        assert json.loads(event.data_json) == {
            "patch_path": f"patches/{task.id}/iteration-0.patch"
        }
    assert reopened.get(task.id).patch_path == absolute_patch
    assert reopened.get(task.id).spec.metadata["source_patch_path"] == str(absolute_patch)
    assert (
        reopened.get_iteration(task.id, 0).worker_transcript_path
        == config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    )
    assert reopened.get(task.id).validations[0].cwd == config.worktrees_dir / task.id
    assert reopened.events(task.id)[1].message == str(absolute_patch)
    assert reopened.events(task.id)[1].data["patch_path"] == str(absolute_patch)
def make_task_stale(store: TaskStore, task_id: str, *, minutes: int = 30) -> None:
    old = utc_now() - timedelta(minutes=minutes)
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task_id)
        assert row is not None
        row.updated_at = old.isoformat()



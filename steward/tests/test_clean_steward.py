from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from urllib.request import (
    BaseHandler,
    HTTPDefaultErrorHandler,
    HTTPErrorProcessor,
    OpenerDirector,
)

import pytest
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from coquic_steward.cli import app
from coquic_steward.agents import CodexRunner, render_worker_prompt
from coquic_steward.agents.diagnostics import diagnostics_for_paths
from coquic_steward.core.config import StewardConfig, StewardLimits, load_config
from coquic_steward.core.lifecycle import InvalidTaskTransition
from coquic_steward.core.models import (
    IntegrationMode,
    Priority,
    ProjectSignals,
    Risk,
    SchedulerWakeupStatus,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    SignalItemStatus,
    TaskKind,
    TaskRecord,
    TaskSpec,
    TaskStatus,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    new_scheduler_wakeup_id,
    new_signal_fetch_id,
    new_task_id,
    utc_now,
)
from coquic_steward.core.subprocesses import CommandResult
from coquic_steward.execution import StewardExecutor, Worktrees
from coquic_steward.execution.executor import (
    commit_message_schema_path,
    parse_commit_message,
    render_commit_message_prompt,
)
from coquic_steward.execution.review import (
    parse_review,
    review_approved,
    review_schema_path,
)
from coquic_steward.orchestration import (
    DaemonAlreadyRunning,
    StewardDaemon,
    StewardPreflightError,
    acquire_daemon_lock,
)
from coquic_steward.orchestration.daemon import (
    DAEMON_EVENT_TASK_ID,
    SchedulerTrigger,
    due_provider_names,
    scheduler_state,
    status_stale_minutes,
    wait_for_scheduler_event,
)
from coquic_steward.planning import (
    CodexPlanner,
    PLANNER_SYSTEM_PROMPT,
    PlannerRun,
    PlanVerifier,
    planner_schema_path,
    planner_thread_path,
)
from coquic_steward.public_mirror import (
    PublicMirrorPublisher,
    public_mirror_payload,
    public_task_detail_payload,
    publish_public_mirror,
    write_public_mirror,
)
from coquic_steward.planning.verifier import ActiveTaskSummary
from coquic_steward.signals import (
    CodacyProvider,
    GitHubActionsCiProvider,
    GitHubActionsInteropProvider,
    GitHubActionsPerfProvider,
    ProviderSignalResult,
    collect_signal_items,
    gather_signals,
)
from coquic_steward.signals.collector import PROVIDER_TYPES
from coquic_steward.storage import TaskStore
from coquic_steward.storage.schema import (
    EventRow,
    SignalItemRow,
    TaskIterationRow,
    TaskRow,
    ValidationRow,
)
from coquic_steward.web.app import TEXT_TAIL_BYTES, create_app


def test_config_defaults_from_repo(repo: Path, coquic_home: Path) -> None:
    config = load_config(repo_root=repo)
    assert config.repo_root == repo
    assert config.steward_home == coquic_home / "steward"
    assert config.state_dir == coquic_home / "steward"
    assert config.db_path == coquic_home / "steward" / "steward.sqlite"
    assert config.db_path.name == "steward.sqlite"
    assert config.legacy_json_path == config.state_dir / "steward.json"
    assert config.worktrees_dir == config.state_dir / "worktrees"
    assert config.transcripts_dir == config.state_dir / "transcripts"
    assert config.integration_mode == "local-only"
    assert config.local_only is False
    assert config.enabled_signals == (
        "github-actions:ci",
        "github-actions:test",
        "github-actions:duvet",
        "github-actions:nightly-ci",
        "github-actions:deploy-demo",
        "github-actions:interop",
        "github-actions:perf",
        "code-scanning",
        "codacy",
    )
    assert config.signal_providers["github-actions:ci"].poll_interval_minutes == 30
    assert config.signal_providers["github-actions:test"].poll_interval_minutes == 30
    assert config.signal_providers["github-actions:duvet"].poll_interval_minutes == 1440
    assert (
        config.signal_providers["github-actions:nightly-ci"].idle_poll_interval_minutes
        == 1440
    )
    assert config.signal_providers["code-scanning"].poll_interval_minutes == 360
    assert config.signal_providers["codacy"].poll_interval_minutes == 360


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


def test_config_reads_signal_provider_polling(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.signals]
enabled = ["codacy"]

[steward.signals.codacy]
poll_interval_minutes = 720
error_retry_minutes = 45
idle_poll_interval_minutes = 5
suppression_hours = 12
max_items = 25
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)
    provider = config.signal_providers["codacy"]

    assert provider.poll_interval_minutes == 720
    assert provider.error_retry_minutes == 45
    assert provider.idle_poll_interval_minutes == 5
    assert provider.suppression_hours == 12
    assert provider.max_items == 25


def test_config_reads_public_mirror(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.public_mirror]
enabled = true
output_path = "public/steward/status.json"
publish = true
transcript_mode = "raw"
remote_user = "deploy"
remote_host = "example.test"
remote_port = 2222
remote_path = "/srv/site/public/steward/status.json"
ssh_key_path = "~/.ssh/steward"
known_hosts_path = "~/.ssh/known_hosts"
connect_timeout_seconds = 7
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    mirror = config.public_mirror
    assert mirror.enabled is True
    assert mirror.output_path == Path("public/steward/status.json")
    assert mirror.publish is True
    assert mirror.transcript_mode == "raw"
    assert mirror.remote_user == "deploy"
    assert mirror.remote_host == "example.test"
    assert mirror.remote_port == 2222
    assert mirror.remote_path == "/srv/site/public/steward/status.json"
    assert mirror.ssh_key_path == Path("~/.ssh/steward").expanduser()
    assert mirror.known_hosts_path == Path("~/.ssh/known_hosts").expanduser()
    assert mirror.connect_timeout_seconds == 7


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


def test_config_reads_validation_timeout_limit(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.limits]
validation_timeout_minutes = 9
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.limits.validation_timeout_minutes == 9


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


def test_timestamped_model_ids_use_compact_utc_timestamp(monkeypatch) -> None:
    monkeypatch.setattr(
        "coquic_steward.core.models.utc_now",
        lambda: datetime(2026, 6, 23, 12, 34, 56, 789, tzinfo=timezone.utc),
    )

    ids = [
        new_task_id(),
        new_signal_fetch_id(),
        new_scheduler_wakeup_id(),
    ]

    parts = [value.rsplit("-", 2) for value in ids]

    assert [(prefix, timestamp) for prefix, timestamp, _ in parts] == [
        ("task", "20260623123456"),
        ("signal-fetch", "20260623123456"),
        ("wakeup", "20260623123456"),
    ]
    assert all(len(random_suffix) == 8 for _, _, random_suffix in parts)


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


def test_store_notifies_after_task_state_change(config: StewardConfig) -> None:
    changes = 0

    def on_change() -> None:
        nonlocal changes
        changes += 1

    store = TaskStore(config.db_path, on_change=on_change)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    before = changes

    store.start_worker(task.id, "worker started")

    assert changes > before
    assert store.get(task.id).status == TaskStatus.running


def test_daemon_cleans_recovered_stale_task_worktree(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree = config.worktrees_dir / task.id
    worktree.mkdir(parents=True)
    (worktree / "README.md").write_text("stale\n", encoding="utf-8")
    task.worktree_path = worktree
    store.save(task)
    store.start_worker(task.id, "worker started")
    make_task_stale(store, task.id)

    result = StewardDaemon(config, store).tick(plan=False, dispatch=False)

    assert result.recovered == 1
    assert store.get(task.id).status == TaskStatus.failed
    assert not worktree.exists()
    assert any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_daemon_does_not_clean_external_recovered_stale_worktree(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    external = tmp_path / "external-worktree"
    external.mkdir()
    task.worktree_path = external
    store.save(task)
    store.start_worker(task.id, "worker started")
    make_task_stale(store, task.id)

    result = StewardDaemon(config, store).tick(plan=False, dispatch=False)

    assert result.recovered == 1
    assert store.get(task.id).status == TaskStatus.failed
    assert external.exists()
    assert not any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_daemon_marks_dispatch_exception_failed(config: StewardConfig, monkeypatch) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree = config.worktrees_dir / task.id
    worktree.mkdir(parents=True)
    task.worktree_path = worktree
    store.save(task)

    def fail_after_start(self, task_id: str) -> bool:
        self.store.start_worker(task_id, "worker started")
        raise RuntimeError("codex stream crashed")

    monkeypatch.setattr(StewardExecutor, "run_task", fail_after_start)

    result = StewardDaemon(config, store).tick(plan=False, max_dispatch=1)

    saved = store.get(task.id)
    assert result.dispatched == 0
    assert result.skipped == 1
    assert saved.status == TaskStatus.failed
    assert saved.summary == "dispatch failed: codex stream crashed"
    assert not worktree.exists()
    events = store.events(task.id)
    assert any(event.kind == "dispatch.failed" for event in events)
    assert any(event.kind == "worktree.cleaned" for event in events)


def test_daemon_marks_early_dispatch_exception_failed(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fail_before_start(self, _task_id: str) -> bool:
        raise RuntimeError("codex failed before start")

    monkeypatch.setattr(StewardExecutor, "run_task", fail_before_start)

    result = StewardDaemon(config, store).tick(plan=False, max_dispatch=1)

    saved = store.get(task.id)
    assert result.skipped == 1
    assert saved.status == TaskStatus.failed
    assert saved.summary == "dispatch failed: codex failed before start"
    assert any(event.kind == "dispatch.failed" for event in store.events(task.id))


def test_store_keeps_integrating_source_with_queued_integration(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.start_integration(source.id, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={"source_task_id": source.id},
        )
    )
    make_task_stale(store, source.id)
    make_task_stale(store, integration.id)

    recovered = store.recover_stale_active_tasks(stale_after_minutes=10)

    assert recovered == []
    assert store.get(source.id).status == TaskStatus.integrating
    assert store.get(integration.id).status == TaskStatus.queued


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


def test_store_tracks_signal_items_independently(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    item, created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="SC2034 in scripts/fuzz-targets.sh:9",
            location={"path": "scripts/fuzz-targets.sh", "line": 9},
            payload={
                "rule_id": "shellcheck_SC2034",
            },
        )
    )
    duplicate, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="SC2034 in scripts/fuzz-targets.sh:9",
        )
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate.id == item.id
    assert [pending.id for pending in store.pending_signal_items()] == ["wi-codacy-1"]


def test_store_records_scheduler_wakeups_for_actionable_changes(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, created = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    item, item_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy finding",
        )
    )

    assert created
    assert item_created
    wakeups = store.pending_wakeups()
    assert [wakeup.reason for wakeup in wakeups] == [
        "task.created",
        "signal.pending",
    ]
    assert wakeups[0].data["task_id"] == task.id
    assert wakeups[1].data["signal_item_id"] == item.id

    assert store.consume_wakeups([wakeup.id for wakeup in wakeups]) == 2
    assert store.pending_wakeups() == []
    assert [wakeup.status for wakeup in store.recent_wakeups()] == [
        SchedulerWakeupStatus.consumed,
        SchedulerWakeupStatus.consumed,
    ]


def test_store_suppresses_recent_duplicate_signal_fingerprints(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    first, created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    second, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )

    assert created
    assert not duplicate_created
    assert second.id == first.id
    assert len(store.pending_signal_items()) == 1


def test_store_requeues_planned_signal_after_recent_fetch_refresh(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.finish_task(task.id, TaskStatus.pushed, "pushed")
    first, created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=25)
    recent = utc_now() - timedelta(minutes=5)
    with Session(store.engine) as session, session.begin():
        row = session.get(SignalItemRow, first.id)
        assert row is not None
        row.planned_at = old.isoformat()
        row.updated_at = recent.isoformat()

    second, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )

    assert duplicate_created
    assert second.id != first.id
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    refreshed = store.list_signal_items(status=SignalItemStatus.planned)[0]
    assert refreshed.id == first.id


def test_store_requeues_planned_signal_after_configured_suppression(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    first, created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=2)
    with Session(store.engine) as session, session.begin():
        row = session.get(SignalItemRow, first.id)
        assert row is not None
        row.planned_at = old.isoformat()
        row.updated_at = old.isoformat()

    second, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )

    assert duplicate_created
    assert second.id != first.id
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    refreshed = store.list_signal_items(status=SignalItemStatus.planned)[0]
    assert refreshed.id == first.id


def test_store_suppresses_planned_signal_while_task_is_active(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=2)
    with Session(store.engine) as session, session.begin():
        row = session.get(SignalItemRow, first.id)
        assert row is not None
        row.planned_at = old.isoformat()
        row.updated_at = old.isoformat()

    second, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-codacy-2",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        ),
        suppression_hours=1,
    )

    assert not duplicate_created
    assert second.id == first.id
    assert store.pending_signal_items() == []


def test_store_marks_signal_items_planned(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    store.add_signal_item(
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
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
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
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


def test_daemon_tick_recovers_stale_task_before_planning(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="old",
            prompt="old",
        ),
        dedupe_key="code-quality:current",
    )
    store.update_status(task.id, TaskStatus.running, "started")
    make_task_stale(store, task.id)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    store.add_signal_item(
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="Open CodeQL findings",
        )
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda _config, _signals, _active: PlannerRun(
            planned=[
                (
                    TaskSpec(
                        kind=TaskKind.code_quality,
                        worker=WorkerKind.code_quality_janitor,
                        title="new",
                        prompt="new",
                    ),
                    "code-quality:current",
                )
            ],
            accepted_count=1,
            proposed_count=1,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
        ),
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.recovered == 1
    assert result.enqueued == 1
    assert store.get(task.id).status == TaskStatus.failed


def test_daemon_recovers_stale_reviewing_task_with_review_timeout(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(
                worker_timeout_minutes=120,
                review_timeout_minutes=20,
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    reviewing, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="R", prompt="R")
    )
    running, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="W", prompt="W")
    )
    store.start_worker(reviewing.id, "worker started")
    store.start_review(reviewing.id, "review started")
    store.start_worker(running.id, "worker started")
    make_task_stale(store, reviewing.id)
    make_task_stale(store, running.id)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda _config, _signals, _active: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
        ),
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.recovered == 1
    assert store.get(reviewing.id).status == TaskStatus.failed
    assert store.get(reviewing.id).summary == "stale active task recovered after 25 minutes"
    assert store.get(running.id).status == TaskStatus.running
    recovered = next(
        event for event in store.events(reviewing.id) if event.kind == "task.recovered_stale"
    )
    assert recovered.data["previous_status"] == "reviewing"
    assert recovered.data["stale_after_minutes"] == 25


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
    assert {
        key: recovered_event.data[key]
        for key in ("previous_status", "effective_status", "stale_after_minutes")
    } == {
        "previous_status": "reviewing",
        "effective_status": "running",
        "stale_after_minutes": 125,
    }


def test_status_stale_minutes_respects_explicit_stale_limit(config: StewardConfig) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(
                worker_timeout_minutes=120,
                review_timeout_minutes=20,
                stale_task_minutes=7,
            ),
        }
    )

    assert status_stale_minutes(config) == {}


def test_daemon_lock_rejects_second_owner(config: StewardConfig) -> None:
    with acquire_daemon_lock(config):
        second_lock = acquire_daemon_lock(config)
        second_lock_acquired = False
        with pytest.raises(DaemonAlreadyRunning) as exc_info:
            try:
                second_lock.__enter__()
                second_lock_acquired = True
            finally:
                if second_lock_acquired:
                    second_lock.__exit__(None, None, None)

    assert exc_info.value.lock_path == config.state_dir / "daemon.lock"
    assert "pid=" in exc_info.value.owner
    with acquire_daemon_lock(config):
        pass


def test_daemon_preflights_push_main_remote(
    config: StewardConfig, tmp_path: Path
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    subprocess.run(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
        }
    )
    config.ensure_dirs()
    logs: list[str] = []

    StewardDaemon(config, TaskStore(config.db_path), logger=logs.append)

    assert logs == ["[steward] remote push preflight ok remote=origin branch=main"]


def test_daemon_preflight_fails_before_tick_for_push_main(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
        }
    )
    config.ensure_dirs()

    with pytest.raises(StewardPreflightError) as exc_info:
        StewardDaemon(config, TaskStore(config.db_path))

    assert "remote push preflight failed" in str(exc_info.value)
    assert "fetch remote main" in str(exc_info.value)


def test_daemon_preflight_skips_when_external_writes_disabled(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": True,
        }
    )
    config.ensure_dirs()

    def fail_run_command(*_args, **_kwargs):
        raise AssertionError("preflight should not run in local_only mode")

    monkeypatch.setattr(
        "coquic_steward.orchestration.preflight.run_command", fail_run_command
    )

    StewardDaemon(config, TaskStore(config.db_path))


def test_daemon_logs_planner_lifecycle_event(
    config: StewardConfig, monkeypatch, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    inbox_item, _ = store.add_signal_item(
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="Open CodeQL findings",
            payload={"id": "wi-codeql-1", "provider": "code-scanning", "kind": "codeql-alert"},
        )
    )

    def fake_run_planner(_config, _signals, _active):
        assert [item.id for item in _signals.items] == [inbox_item.id]
        return PlannerRun(
            planned=[
                (
                    TaskSpec(
                        kind=TaskKind.code_quality,
                        worker=WorkerKind.code_quality_janitor,
                        title="CodeQL",
                        prompt="Fix current CodeQL alerts.",
                        metadata={"selected_signal_item_ids": [inbox_item.id]},
                    ),
                    "codeql:open",
                )
            ],
            accepted_count=1,
            proposed_count=2,
            completed=True,
            exit_code=0,
            prompt_path=tmp_path / "planner.md",
            transcript_path=tmp_path / "codex.jsonl",
            thread_id="planner-thread-1",
            consumed_item_ids=[inbox_item.id],
            run_id="planner-run-1",
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        fake_run_planner,
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.enqueued == 1
    events = store.events(DAEMON_EVENT_TASK_ID)
    assert [event.kind for event in events] == ["planner.started", "planner.finished"]
    assert events[0].message == "planner turn started"
    assert events[0].data["active_task_count"] == 0
    assert events[0].data["inbox_item_ids"] == [inbox_item.id]
    assert events[1].message == "accepted 1 of 2 proposed task(s)"
    assert events[1].data["accepted_count"] == 1
    assert events[1].data["proposed_count"] == 2
    assert events[1].data["completed"] is True
    assert events[1].data["exit_code"] == 0
    assert events[1].data["prompt_path"].endswith("planner.md")
    assert events[1].data["transcript_path"].endswith("codex.jsonl")
    assert events[1].data["thread_id"] == "planner-thread-1"
    assert events[1].data["consumed_item_ids"] == [inbox_item.id]
    assert events[1].data["consumed_item_count"] == 1
    assert store.list_signal_items()[0].status == SignalItemStatus.planned


def test_daemon_streams_debug_lines_to_logger(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    lines: list[str] = []
    store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy findings",
        )
    )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda _config, _signals, _active: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id="planner-thread-1",
        ),
    )

    result = StewardDaemon(config, store, logger=lines.append).tick(dispatch=False)

    assert result.enqueued == 0
    assert any("cycle start" in line for line in lines)
    assert any("planner start" in line for line in lines)
    assert any("planner finish" in line for line in lines)
    assert any("verifier=0/0" in line for line in lines)
    assert any("transcript=" in line for line in lines)
    assert any("cycle finish" in line for line in lines)


def test_public_mirror_payload_redacts_internal_state(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title=f"Fix issue in {config.repo_root}/src/main.zig",
            prompt=f"private prompt {config.coquic_home}",
            metadata={
                "local_path": str(config.worktrees_dir / "task"),
                "secret": "do-not-publish",
            },
        )
    )
    task.summary = f"worked in {config.state_dir}/worktrees/{task.id}"
    task.transcript_path = config.transcripts_dir / task.id / "codex.jsonl"
    task.patch_path = config.patches_dir / task.id / "patch.diff"
    task.validations.append(
        ValidationResult(
            command=["test"],
            cwd=config.repo_root,
            passed=False,
            exit_code=1,
            output_path=config.logs_dir / task.id / "validation.txt",
            summary=f"see {config.logs_dir}/private.log",
        )
    )
    store.save(task)
    store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="codacy-1",
            title=f"Open finding at {config.repo_root}/secret.py",
            summary=f"raw {config.coquic_home}",
            payload={"token": "secret"},
            links=[
                {"label": "GitHub", "url": "https://github.com/minhuw/coquic/issues/1"},
                {"label": "internal", "url": "file:///tmp/private"},
            ],
        )
    )
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.error,
            item_count=1,
            error="<urlopen error _ssl.c:1011: The handshake operation timed out>",
        )
    )

    payload = public_mirror_payload(config, store)
    encoded = json.dumps(payload, sort_keys=True)

    assert str(config.repo_root) not in encoded
    assert str(config.coquic_home) not in encoded
    assert str(config.state_dir) not in encoded
    assert "private prompt" not in encoded
    assert "do-not-publish" not in encoded
    assert '"token"' not in encoded
    assert "transcript_path" not in encoded
    assert "patch_path" not in encoded
    assert "payload" not in encoded
    assert payload["tasks"][0]["detail_url"] == f"/steward/tasks/{task.id}"
    assert payload["tasks"][0]["detail_json"] == f"/steward/data/tasks/{task.id}.json"
    assert payload["counts"]["queued"] == 1
    assert payload["counts"]["active"] == 0
    signal = payload["signals"]["items"][0]
    assert signal["links"] == [
        {"label": "GitHub", "url": "https://github.com/minhuw/coquic/issues/1"}
    ]
    assert payload["signals"]["fetches"][0]["error"] == "request timed out"
    codacy_provider = next(
        provider
        for provider in payload["scheduler"]["providers"]
        if provider["provider"] == "codacy"
    )
    assert codacy_provider["last_error"] == "request timed out"


def test_public_mirror_import_does_not_import_daemon(
    repo: Path, coquic_home: Path
) -> None:
    steward_src = Path(__file__).resolve().parents[1] / "src"
    pythonpath = str(steward_src)
    if os.environ.get("PYTHONPATH"):
        pythonpath += os.pathsep + os.environ["PYTHONPATH"]
    script = (
        "import os, sys\n"
        f"os.environ['COQUIC_HOME'] = {str(coquic_home)!r}\n"
        f"os.chdir({str(repo)!r})\n"
        "import coquic_steward.public_mirror\n"
        "assert 'coquic_steward.orchestration.daemon' not in sys.modules\n"
    )
    subprocess.run(
        [sys.executable, "-c", script],
        cwd=repo,
        env={**os.environ, "PYTHONPATH": pythonpath},
        check=True,
    )


def test_public_task_detail_exports_sanitized_artifacts(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title=f"Fix {config.repo_root}/src/main.zig",
            prompt="private prompt must not publish",
            metadata={
                "selected_signal_item_ids": ["wi-1"],
                "source_context": {"payload": {"token": "secret"}},
                "source_patch_path": str(config.patches_dir / "private.patch"),
                "workflow_name": "CI",
            },
        )
    )
    transcript = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(
        "\n".join(
            [
                '{"type":"thread.started","thread_id":"private-thread"}',
                '{"type":"turn.started"}',
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "agent-1",
                            "type": "agent_message",
                            "text": f"edited {config.repo_root}/src/main.zig and /home/minhu/private",
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "cmd-1",
                            "type": "command_execution",
                            "command": "pytest",
                            "status": "completed",
                            "exit_code": 0,
                            "aggregated_output": f"ok {config.state_dir}",
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    last_message = transcript.parent / "last-message.md"
    last_message.write_text(f"done {config.coquic_home}\n", encoding="utf-8")
    patch = config.patches_dir / task.id / "iteration-0.patch"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_text(
        f"diff --git a/src/main.zig b/src/main.zig\n+// {config.repo_root}\n",
        encoding="utf-8",
    )
    validation_log = config.logs_dir / task.id / "validation.txt"
    validation_log.parent.mkdir(parents=True, exist_ok=True)
    validation_log.write_text(f"validated {config.state_dir}\n", encoding="utf-8")
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=transcript,
        worker_last_message_path=last_message,
    )
    store.finish_iteration_worker(
        task.id,
        0,
        WorkerResult(
            completed=True,
            command=["codex"],
            cwd=config.repo_root,
            exit_code=0,
            prompt_path=config.prompts_dir / task.id / "worker.md",
            transcript_path=transcript,
            last_message_path=last_message,
            final_message="done",
        ),
    )
    store.record_iteration_patch(task.id, 0, patch)
    task = store.get(task.id)
    task.patch_path = patch
    task.transcript_path = transcript
    task.last_message_path = last_message
    task.validations.append(
        ValidationResult(
            command=["pytest", str(config.repo_root / "secret.py")],
            cwd=config.repo_root,
            passed=True,
            exit_code=0,
            output_path=validation_log,
            summary=f"checked {config.logs_dir}",
            iteration=0,
        )
    )
    store.save(task)
    store.add_event(
        task.id,
        "patch.saved",
        f"saved {patch}",
        {"patch_path": str(patch), "summary": f"patch in {config.repo_root}"},
    )

    detail = public_task_detail_payload(config, store, task.id)
    encoded = json.dumps(detail, sort_keys=True)

    assert "private prompt" not in encoded
    assert detail["task"]["spec"]["prompt"] == ""
    assert "private-thread" not in encoded
    assert "prompt_path" not in encoded
    assert "patch_path" not in encoded
    assert "source_patch_path" not in encoded
    assert "transcript_path" not in encoded
    assert str(config.repo_root) not in encoded
    assert str(config.coquic_home) not in encoded
    assert str(config.state_dir) not in encoded
    assert "/home/minhu" not in encoded
    assert "[repo]/src/main.zig" in encoded
    assert "[local-path]" in encoded
    assert "[steward-state]" in encoded
    assert detail["attempts"][0]["patch"]["text"].startswith("diff --git")
    assert "thread.started" not in detail["attempts"][0]["worker"]["transcript"]["text"]
    assert detail["attempts"][0]["validations"][0]["log"]["text"].strip()


def test_write_public_mirror_writes_task_details(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    path = write_public_mirror(config, store)

    assert path.exists()
    assert (path.parent / "data" / "tasks" / "index.json").exists()
    detail_path = path.parent / "data" / "tasks" / f"{task.id}.json"
    assert detail_path.exists()
    detail = json.loads(detail_path.read_text(encoding="utf-8"))
    assert detail["task"]["id"] == task.id
    index = json.loads(
        (path.parent / "data" / "tasks" / "index.json").read_text(encoding="utf-8")
    )
    assert index["tasks"][0]["detail_json"] == f"/steward/data/tasks/{task.id}.json"


def test_write_public_mirror_raw_transcript_mode_publishes_original_transcript(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                output_path=Path("public/steward/status.json"),
                transcript_mode="raw",
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="Publish transcript",
            prompt="private prompt must not publish",
        )
    )
    transcript = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript_text = "\n".join(
        [
            json.dumps({"type": "thread.started", "thread_id": "private-thread"}),
            json.dumps({"type": "turn.started"}),
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": (
                            f"edited {config.repo_root}/src/main.zig "
                            "and /home/minhu/private"
                        ),
                    },
                }
            ),
        ]
    ) + "\n"
    transcript.write_text(transcript_text, encoding="utf-8")
    prompt = config.prompts_dir / task.id / "worker.md"
    prompt.parent.mkdir(parents=True, exist_ok=True)
    prompt.write_text("do not publish prompt\n", encoding="utf-8")
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=prompt,
        worker_transcript_path=transcript,
        worker_last_message_path=None,
    )
    task = store.get(task.id)
    task.transcript_path = transcript
    store.save(task)

    path = write_public_mirror(config, store)
    detail_path = path.parent / "data" / "tasks" / f"{task.id}.json"
    detail = json.loads(detail_path.read_text(encoding="utf-8"))
    artifact = detail["attempts"][0]["worker"]["transcript"]
    raw_path = path.parent / artifact["url"].removeprefix("/steward/")
    encoded_detail = json.dumps(detail, sort_keys=True)
    mirror_files = list(path.parent.rglob("*"))

    assert artifact["mode"] == "raw"
    assert artifact["text"] == ""
    assert artifact["size"] == len(transcript_text.encode("utf-8"))
    assert raw_path.exists()
    assert raw_path.read_text(encoding="utf-8") == transcript_text
    assert artifact["sha256"] == sha256(transcript_text.encode("utf-8")).hexdigest()
    assert detail["task"]["spec"]["prompt"] == "private prompt must not publish"
    assert "private-thread" in raw_path.read_text(encoding="utf-8")
    assert "/home/minhu/private" in raw_path.read_text(encoding="utf-8")
    assert "private-thread" not in encoded_detail
    assert "prompt_path" not in encoded_detail
    assert all(file.name != "worker.md" for file in mirror_files)


def test_public_mirror_force_publish_ignores_disabled_upload(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    calls: list[Path] = []

    def fake_publish(
        self: PublicMirrorPublisher, local_path: Path, *, cwd: Path
    ) -> CommandResult:
        calls.append(local_path)
        return CommandResult(
            args=["fake-publish"],
            cwd=cwd,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(PublicMirrorPublisher, "publish", fake_publish)

    path, result = publish_public_mirror(config, store, force=True)

    assert calls == [path]
    assert result is not None
    assert result.ok
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["tasks"][0]["id"] == task.id


def test_public_mirror_publish_flag_can_skip_configured_upload(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                publish=True,
                output_path=Path("public/steward/status.json"),
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    calls = 0

    def fake_publish(
        self: PublicMirrorPublisher, local_path: Path, *, cwd: Path
    ) -> CommandResult:
        nonlocal calls
        calls += 1
        return CommandResult(
            args=["fake-publish"],
            cwd=cwd,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(PublicMirrorPublisher, "publish", fake_publish)

    path, result = publish_public_mirror(config, store, publish=False)

    assert path.exists()
    assert result is None
    assert calls == 0


def test_daemon_public_mirror_writes_on_state_change(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                enabled=True,
                output_path=Path("public/steward/status.json"),
                publish=False,
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    daemon = StewardDaemon(config, store)

    def fake_run(task_id: str) -> bool:
        store.start_worker(task_id, "worker started")
        path = config.state_dir / "public" / "steward" / "status.json"
        assert path.exists()
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["state"] == "working"
        assert payload["counts"]["active"] == 1
        store.finish_task(task_id, TaskStatus.succeeded, "done")
        return True

    monkeypatch.setattr(daemon.executor, "run_task", fake_run)

    result = daemon.tick(plan=False, dispatch=True)

    path = config.state_dir / "public" / "steward" / "status.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert result.dispatched == 1
    assert payload["state"] == "idle"
    assert payload["counts"]["completed"] == 1
    assert payload["tasks"][0]["id"] == task.id


def test_daemon_store_change_mirror_update_skips_remote_publish(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                enabled=True,
                publish=True,
                output_path=Path("public/steward/status.json"),
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    calls = 0

    def fake_publish(
        self: PublicMirrorPublisher, local_path: Path, *, cwd: Path
    ) -> CommandResult:
        nonlocal calls
        calls += 1
        return CommandResult(
            args=["fake-publish"],
            cwd=cwd,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(PublicMirrorPublisher, "publish", fake_publish)
    StewardDaemon(config, store)

    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    path = config.state_dir / "public" / "steward" / "status.json"
    assert path.exists()
    assert calls == 0


def test_daemon_cycle_mirror_update_respects_disabled_publish(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "public_mirror": config.public_mirror.__class__(
                enabled=True,
                publish=False,
                output_path=Path("public/steward/status.json"),
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    calls = 0

    def fake_publish(
        self: PublicMirrorPublisher, local_path: Path, *, cwd: Path
    ) -> CommandResult:
        nonlocal calls
        calls += 1
        return CommandResult(
            args=["fake-publish"],
            cwd=cwd,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(PublicMirrorPublisher, "publish", fake_publish)

    result = StewardDaemon(config, store).tick(plan=False, dispatch=False)

    path = config.state_dir / "public" / "steward" / "status.json"
    assert result.dispatched == 0
    assert path.exists()
    assert calls == 0


def test_daemon_replans_after_successful_dispatch(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    queued, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    planned_specs = [
        [],
        [
            (
                TaskSpec(
                    kind=TaskKind.custom,
                    worker=WorkerKind.custom,
                    title="follow-up",
                    prompt="follow-up",
                ),
                "follow-up",
            )
        ],
    ]

    def fake_plan(_config, _signals, _active):
        planned = planned_specs.pop(0)
        return PlannerRun(
            planned=planned,
            accepted_count=len(planned),
            proposed_count=len(planned),
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
        )

    def fake_run(task_id: str) -> bool:
        store.update_status(task_id, TaskStatus.succeeded, "done")
        return True

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy findings",
        )
    )
    monkeypatch.setattr("coquic_steward.orchestration.daemon.run_planner", fake_plan)
    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "run_task", fake_run)

    result = daemon.tick(plan=True, dispatch=True, max_dispatch=1)

    assert result.dispatched == 1
    assert result.planned == 1
    assert result.enqueued == 1
    assert store.get(queued.id).status == TaskStatus.succeeded


def test_daemon_dispatches_newly_queued_integration_continuation(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=1, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_run(task_id: str) -> bool:
        task = store.get(task_id)
        if task.spec.worker == WorkerKind.integration_manager:
            store.finish_task(task.id, TaskStatus.succeeded, "integrated")
            store.finish_task(source.id, TaskStatus.succeeded, "integrated")
            return True
        integration, _ = store.add_task(
            TaskSpec(
                kind=TaskKind.integration,
                worker=WorkerKind.integration_manager,
                title="integrate",
                prompt="integrate",
                metadata={"source_task_id": source.id},
            ),
            dedupe_key=f"integration:{source.id}",
        )
        store.start_integration(source.id, f"integration queued: {integration.id}")
        return True

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "run_task", fake_run)

    result = daemon.tick(plan=False, dispatch=True)

    integration_tasks = [
        task
        for task in store.list_tasks()
        if task.spec.worker == WorkerKind.integration_manager
    ]
    assert result.dispatched == 2
    assert len(integration_tasks) == 1
    assert integration_tasks[0].status == TaskStatus.succeeded
    assert store.get(source.id).status == TaskStatus.succeeded


def test_daemon_dispatch_skips_full_integration_lane_for_source_capacity(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=1, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    active_integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="active integration",
            prompt="integrate",
        )
    )
    store.update_status(active_integration.id, TaskStatus.running, "started")
    queued_integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="queued integration",
            prompt="integrate",
        )
    )
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    ran: list[str] = []

    def fake_run(task_id: str) -> bool:
        ran.append(task_id)
        store.update_status(task_id, TaskStatus.succeeded, "done")
        return True

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "run_task", fake_run)

    result = daemon.tick(plan=False, dispatch=True)

    assert result.dispatched == 1
    assert ran == [source.id]
    assert store.get(queued_integration.id).status == TaskStatus.queued


def test_daemon_forever_dispatches_one_task_per_cycle(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    daemon = StewardDaemon(config, store)
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.wait_for_scheduler_event",
        lambda *_args: SchedulerTrigger(reason="wakeup", providers=[]),
    )

    def fake_run_cycle(**kwargs) -> None:
        calls.append(kwargs)
        raise StopIteration

    monkeypatch.setattr(daemon, "run_cycle", fake_run_cycle)

    with pytest.raises(StopIteration):
        daemon.run_forever()

    assert calls == [{"fetch_providers": [], "max_dispatch": 1, "reason": "wakeup"}]


def test_daemon_skips_signal_fetch_when_active_capacity_is_full(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=1, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    active, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.update_status(active.id, TaskStatus.running, "started")
    called = False

    def fake_collect(_config):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: pytest.fail("planner should not run at capacity"),
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert called is False
    assert result.signal_fetches == 0
    assert result.enqueued == 0


def test_daemon_local_wakeup_fetches_idle_due_signals_when_idle(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("code-scanning", "codacy"),
            "signal_providers": {
                "code-scanning": config.signal_providers["code-scanning"].__class__(
                    poll_interval_minutes=360,
                    idle_poll_interval_minutes=1,
                ),
                "codacy": config.signal_providers["codacy"].__class__(
                    poll_interval_minutes=360,
                    idle_poll_interval_minutes=30,
                ),
            },
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=2)
    for provider in config.enabled_signals:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=fetched_at,
                completed_at=fetched_at,
                item_count=0,
                new_item_count=0,
                summary="none",
            )
        )
    store.request_wakeup("task.status", {"task_id": "task-1"})
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.transcripts_dir / "planner" / "codex.jsonl",
        ),
    )

    result = StewardDaemon(config, store).run_cycle(dispatch=False, reason="wakeup")

    assert fetched == [["code-scanning"]]
    assert result.signal_fetches == 0
    assert store.pending_wakeups() == []


def test_daemon_idle_signal_fetch_waits_for_existing_local_work(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    store.request_wakeup("task.status", {"task_id": "task-1"})
    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: pytest.fail("planner should not run before queued work"),
    )

    result = StewardDaemon(config, store).run_cycle(plan=True, dispatch=False, reason="wakeup")

    assert fetched == []
    assert result.signal_fetches == 0
    assert store.pending_wakeups() == []


def test_daemon_idle_signal_fetch_waits_for_pending_signal_items(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    store.request_wakeup("task.status", {"task_id": "task-1"})
    store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="pending",
            title="Pending finding",
        )
    )
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[],
        ),
    )

    result = StewardDaemon(config, store).run_cycle(plan=True, dispatch=False, reason="wakeup")

    assert fetched == []
    assert result.signal_fetches == 0
    assert result.planned == 0
    assert store.pending_wakeups() == []


def test_daemon_fetches_selected_providers_from_force_wakeup(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    store.request_wakeup("signal.fetch", {"providers": ["codacy"]})
    fetched: list[list[str]] = []

    def fake_collect(_config, *, provider_names=None):
        fetched.append(list(provider_names or []))
        return []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        fake_collect,
    )

    result = StewardDaemon(config, store).run_cycle(dispatch=False, reason="wakeup")

    assert fetched == [["codacy"]]
    assert result.signal_fetches == 0
    assert store.pending_wakeups() == []


def test_scheduler_state_tracks_provider_due_times(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)

    initial = scheduler_state(config, store)

    assert due_provider_names(config, store) == list(config.enabled_signals)
    assert all(provider.due for provider in initial.providers)

    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            item_count=0,
            new_item_count=0,
            summary="none",
        )
    )
    state = scheduler_state(config, store)
    codacy = next(provider for provider in state.providers if provider.provider == "codacy")

    assert codacy.due is False
    assert codacy.poll_interval_minutes == 360
    assert codacy.idle_poll_interval_minutes == 30
    assert codacy.next_due_at > codacy.last_fetch_at
    assert codacy.idle_next_due_at == codacy.last_fetch_at + timedelta(minutes=30)
    assert codacy.idle_due is False


def test_wait_for_scheduler_event_returns_due_providers(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "provider-due"
    assert trigger.providers == list(config.enabled_signals)


def test_wait_for_scheduler_event_prioritizes_pending_wakeup(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    store.request_wakeup("task.created")

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "wakeup"
    assert trigger.providers == []


def test_wait_for_scheduler_event_fetches_signals_when_idle(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("code-scanning", "codacy"),
            "signal_providers": {},
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=31)
    for provider in config.enabled_signals:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=fetched_at,
                completed_at=fetched_at,
                item_count=0,
                new_item_count=0,
                summary="none",
            )
        )

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "idle-fetch"
    assert trigger.providers == list(config.enabled_signals)


def test_wait_for_scheduler_event_uses_configured_idle_poll_interval(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
            "signal_providers": {
                "codacy": config.signal_providers["codacy"].__class__(
                    poll_interval_minutes=360,
                    idle_poll_interval_minutes=1,
                )
            },
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=2)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            started_at=fetched_at,
            completed_at=fetched_at,
            item_count=0,
            new_item_count=0,
            summary="none",
        )
    )

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "idle-fetch"
    assert trigger.providers == ["codacy"]


def test_wait_for_scheduler_event_coalesces_near_idle_fetches(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("code-scanning", "codacy"),
            "signal_providers": {},
            "scheduler_wait_interval_sec": 2.0,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    first_due = utc_now() - timedelta(minutes=31)
    second_due_soon = utc_now() - timedelta(minutes=30) + timedelta(seconds=1)
    for provider, fetched_at in [
        ("code-scanning", first_due),
        ("codacy", second_due_soon),
    ]:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=fetched_at,
                completed_at=fetched_at,
                item_count=0,
                new_item_count=0,
                summary="none",
            )
        )

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "idle-fetch"
    assert trigger.providers == ["code-scanning", "codacy"]


def test_wait_for_scheduler_event_does_not_idle_fetch_with_queued_work(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
            "signal_providers": {},
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            started_at=utc_now() - timedelta(minutes=31),
            completed_at=utc_now() - timedelta(minutes=31),
            item_count=0,
            new_item_count=0,
            summary="none",
        )
    )
    store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.consume_wakeups([wakeup.id for wakeup in store.pending_wakeups()])
    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        raise StopIteration

    monkeypatch.setattr("coquic_steward.orchestration.daemon.time.sleep", fake_sleep)

    with pytest.raises(StopIteration):
        wait_for_scheduler_event(config, store)

    assert sleep_calls == [pytest.approx(config.scheduler_wait_interval_sec)]


def test_daemon_plans_bounded_signal_item_inbox(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(max_active_tasks=2, worker_timeout_minutes=1),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    for index in range(5):
        store.add_signal_item(
            SignalItem(
                id=f"wi-codacy-{index}",
                provider="codacy",
                kind="codacy.issue",
                fingerprint=f"wi-codacy-{index}",
                title=f"Codacy finding {index}",
                payload={"id": f"wi-codacy-{index}", "kind": "codacy-issue"},
            )
        )
    seen_batches: list[list[str]] = []

    def fake_plan(_config, signals, _active):
        batch = [item.id for item in signals.items]
        seen_batches.append(batch)
        selected = batch[0]
        return PlannerRun(
            planned=[
                (
                    TaskSpec(
                        kind=TaskKind.code_quality,
                        worker=WorkerKind.code_quality_janitor,
                        title=f"Fix {selected}",
                        prompt=f"Fix {selected}",
                        metadata={"selected_signal_item_ids": [selected]},
                    ),
                    f"codacy:{selected}",
                )
            ],
            accepted_count=1,
            proposed_count=1,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[selected],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr("coquic_steward.orchestration.daemon.run_planner", fake_plan)

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.enqueued == 2
    assert seen_batches == [
        ["wi-codacy-0", "wi-codacy-1"],
        ["wi-codacy-1", "wi-codacy-2"],
    ]
    planned = {
        item.id for item in store.list_signal_items(status=SignalItemStatus.planned)
    }
    pending = {item.id for item in store.pending_signal_items()}
    assert planned == {"wi-codacy-0", "wi-codacy-1"}
    assert pending == {"wi-codacy-2", "wi-codacy-3", "wi-codacy-4"}


def test_plan_verifier_rejects_broken_and_duplicate_specs() -> None:
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[
            SignalItem(
                id="wi-codeql-1",
                provider="code-scanning",
                kind="code-scanning.alert",
                fingerprint="wi-codeql-1",
                title="Open CodeQL findings",
            )
        ],
    )
    active = [
        ActiveTaskSummary(
            id="task-1",
            kind="code-quality",
            worker="code-quality-janitor",
            title="Active CodeQL fix",
            status="running",
            dedupe_key="codeql:open",
        )
    ]

    planned = PlanVerifier().verify(
        """
        {
          "tasks": [
            {
              "dedupe_key": "codeql:open",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Duplicate",
              "prompt": "Fix the current CodeQL alerts.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codeql-1"]
            },
            {
              "dedupe_key": "bad",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Bad evidence",
              "prompt": "Fix a made-up alert.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["codeql:missing"]
            }
          ]
        }
        """,
        signals,
        active,
    )

    assert planned == []


def test_plan_verifier_accepts_valid_llm_proposal() -> None:
    item = SignalItem(
        id="wi-codeql-1",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="wi-codeql-1",
        title="cpp/use-after-free in src/main.cpp:12",
        summary="CodeQL sampled 1 open finding(s)",
        location={"path": "src/main.cpp", "line": 12},
        payload={"rule_id": "cpp/use-after-free"},
    )
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[item],
    )

    planned = PlanVerifier().verify(
        """
        {
          "tasks": [
            {
              "dedupe_key": "codeql:open",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Fix current CodeQL alerts",
              "prompt": "Fetch current CodeQL alerts, fix source issues, and validate locally.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codeql-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-codeql-1"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert len(planned) == 1
    spec, dedupe_key = planned[0]
    assert spec.kind == TaskKind.code_quality
    assert dedupe_key == "codeql:open"
    assert spec.metadata["evidence"] == ["wi-codeql-1"]
    assert spec.metadata["source_context"]["selected_signal_item_ids"] == [
        "wi-codeql-1"
    ]
    assert spec.metadata["source_context"]["selected_signal_items"][0]["id"] == item.id


def test_plan_verifier_accepts_item_backed_llm_proposal() -> None:
    item = SignalItem(
        id="wi-codeql-1",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="wi-codeql-1",
        title="cpp/use-after-free in src/main.cpp:12",
        summary="CodeQL sampled 1 open finding(s)",
        location={"path": "src/main.cpp", "line": 12},
        payload={"rule_id": "cpp/use-after-free"},
    )
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[item],
    )

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-codeql-1"],
          "tasks": [
            {
              "dedupe_key": "codeql:wi-codeql-1",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Fix cpp/use-after-free in src/main.cpp",
              "prompt": "Fix the selected CodeQL finding and validate locally.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codeql-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-codeql-1"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.consumed_item_ids == ["wi-codeql-1"]
    assert len(verified.planned) == 1
    spec, dedupe_key = verified.planned[0]
    assert dedupe_key == "codeql:wi-codeql-1"
    assert spec.metadata["source_context"]["selected_signal_items"][0]["id"] == item.id


def test_plan_verifier_ignores_proposed_main_write_flags() -> None:
    signals = ProjectSignals(
        repository="minhuw/coquic",
        items=[
            SignalItem(
                id="wi-codacy-1",
                provider="codacy",
                kind="codacy.issue",
                fingerprint="wi-codacy-1",
                title="Codacy issue",
            )
        ],
    )

    planned = PlanVerifier().verify(
        """
        {
          "tasks": [
            {
              "dedupe_key": "codacy:open",
              "kind": "code-quality",
              "worker": "code-quality-janitor",
              "title": "Fix current Codacy findings",
              "prompt": "Fix the selected Codacy source-context findings and validate locally.",
              "priority": "high",
              "risk": "medium",
              "evidence": ["wi-codacy-1"],
              "metadata": {"selected_signal_item_ids": ["wi-codacy-1"]},
              "allow_main_write": true
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert len(planned) == 1
    assert planned[0][0].allow_main_write is False


def test_codex_planner_prompt_includes_active_tasks(
    config: StewardConfig, tmp_path: Path
) -> None:
    captured_prompt = tmp_path / "prompt.txt"
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" >> {tmp_path / 'args.txt'}\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        f"cat > {captured_prompt}\n"
        'mkdir -p "$(dirname "$last")"\n'
        'printf \'{"tasks":[]}\\n\' > "$last"\n'
        'printf \'{"type":"thread.started","thread_id":"planner-thread-1"}\\n\'\n'
        'printf \'{"message":"{\\"tasks\\":[] }"}\\n\'\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    active, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.interop,
            worker=WorkerKind.interop_doctor,
            title="Debug failed interop run 100",
            prompt="fix interop",
        ),
        dedupe_key="interop:100",
    )

    planned = CodexPlanner(config).plan(
        ProjectSignals(
            repository="minhuw/coquic",
            items=[
                SignalItem(
                    id="wi-interop-100",
                    provider="github-actions:interop",
                    kind="github-actions.interop-failure",
                    fingerprint="wi-interop-100",
                    title="Interop workflow failed",
                    payload={
                        "run_id": "100",
                        "workflow_name": "Interop",
                        "workflow_file": "interop.yml",
                    },
                )
            ],
        ),
        [active],
    )

    assert planned == []
    prompt = captured_prompt.read_text(encoding="utf-8")
    assert PLANNER_SYSTEM_PROMPT.strip() in prompt
    assert "active_tasks" in prompt
    assert "Debug failed interop run 100" in prompt
    assert "interop:100" in prompt
    args = (tmp_path / "args.txt").read_text(encoding="utf-8")
    assert "resume" not in args
    assert "--output-schema" in args
    assert str(planner_schema_path(config)) in args
    assert (
        planner_thread_path(config).read_text(encoding="utf-8")
        == "planner-thread-1"
    )

    planned = CodexPlanner(config).plan(
        ProjectSignals(repository="minhuw/coquic"),
        [],
    )

    assert planned == []
    args = (tmp_path / "args.txt").read_text(encoding="utf-8").splitlines()
    resume_index = args.index("resume")
    session_index = args.index("planner-thread-1")
    assert resume_index < session_index
    assert args[session_index + 1] == "-"


def test_codex_runner_places_resume_options_before_session(
    config: StewardConfig, tmp_path: Path
) -> None:
    runner = CodexRunner(config)
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")
    last_message = tmp_path / "last.md"

    args = runner._args(
        config.repo_root,
        last_message,
        output_schema=schema,
        resume_session="planner-thread-1",
    )

    assert args[:3] == [config.codex_bin, "exec", "resume"]
    assert args[-2:] == ["planner-thread-1", "-"]
    assert args.index("--output-schema") < args.index("planner-thread-1")
    assert "--cd" not in args
    assert "--sandbox" not in args


def test_codex_runner_review_uses_structured_exec(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{tmp_path / "args.txt"}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'printf \'{"verdict":"approve","summary":"ok","findings":[],"validation_gaps":[],"remaining_risk":""}\\n\' > "$last"\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    runner = CodexRunner(config)
    task, _ = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    schema = tmp_path / "review.schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")

    result = runner.run_review(task, "review prompt", config.repo_root, output_schema=schema)
    args = (tmp_path / "args.txt").read_text(encoding="utf-8").splitlines()

    assert result.completed
    assert args[:2] == ["exec", "--json"]
    assert "review" not in args
    assert args[-1] == "-"
    assert args.index("--cd") < args.index("--output-last-message")
    assert "--skip-git-repo-check" not in args
    assert "/reviewer/" in args[args.index("--output-last-message") + 1]
    assert args[args.index("--output-schema") + 1] == str(schema)


def test_codex_review_failure_uses_stderr_summary(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'printf "error: bad review invocation\\n" >&2\n'
        "exit 2\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task, _ = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    schema = tmp_path / "review.schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")

    result = CodexRunner(config).run_review(task, "review prompt", config.repo_root, output_schema=schema)

    assert not result.completed
    assert result.exit_code == 2
    assert result.final_message == "error: bad review invocation"
    assert result.diagnostics["status"] == "failed"
    assert result.diagnostics["last_error"] == "error: bad review invocation"


def test_codex_diagnostics_detect_missing_last_message(tmp_path: Path) -> None:
    transcript = tmp_path / "codex.jsonl"
    last_message = tmp_path / "last-message.md"
    transcript.write_text(
        '{"type":"thread.started","thread_id":"thread-1"}\n'
        '{"type":"turn.started"}\n'
        '{"type":"item.started","item":{"id":"item_0","type":"command_execution","status":"in_progress","command":"date"}}\n',
        encoding="utf-8",
    )

    diagnostics = diagnostics_for_paths(
        transcript_path=transcript,
        last_message_path=last_message,
        completed=False,
    )

    assert diagnostics.status == "abandoned"
    assert diagnostics.last_message_present is False
    assert diagnostics.thread_id == "thread-1"
    assert diagnostics.last_item_type == "command_execution"
    assert diagnostics.last_item_status == "in_progress"


def test_codex_review_uses_review_timeout(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        "sleep 5\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "limits": StewardLimits(
                worker_timeout_minutes=10,
                review_timeout_minutes=0,
            ),
        }
    )
    config.ensure_dirs()
    task, _ = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    schema = tmp_path / "review.schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")

    result = CodexRunner(config).run_review(
        task, "review prompt", config.repo_root, output_schema=schema
    )

    assert not result.completed
    assert result.exit_code == 124
    assert "timed out after 0 minute(s)" in result.final_message


def test_codex_planner_persists_thread_id_on_failed_turn(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'broken planner turn\\n' > \"$last\"\n"
        'printf \'{"type":"thread.started","thread_id":"planner-thread-failed"}\\n\'\n'
        "exit 1\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()

    planned = CodexPlanner(config).plan(
        ProjectSignals(repository="minhuw/coquic"),
        [],
    )

    assert planned == []
    assert (
        planner_thread_path(config).read_text(encoding="utf-8")
        == "planner-thread-failed"
    )


def test_planner_schema_file_matches_expected_shape(config: StewardConfig) -> None:
    path = planner_schema_path(config)
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == ["consumed_item_ids", "tasks"]
    assert schema["properties"]["consumed_item_ids"]["type"] == "array"
    item = schema["properties"]["tasks"]["items"]
    assert "code-quality" in item["properties"]["kind"]["enum"]
    assert schema["additionalProperties"] is False
    assert item["additionalProperties"] is False
    assert item["properties"]["metadata"]["additionalProperties"] is False
    assert item["properties"]["metadata"]["required"] == ["selected_signal_item_ids"]
    assert set(item["properties"]["metadata"]["properties"]) == {
        "selected_signal_item_ids",
    }
    selected_ids = item["properties"]["metadata"]["properties"]["selected_signal_item_ids"]
    assert selected_ids["items"]["type"] == "string"


def test_planner_schema_matches_openai_structured_output_subset(
    config: StewardConfig,
) -> None:
    schema = json.loads(planner_schema_path(config).read_text(encoding="utf-8"))

    assert_openai_structured_output_schema(schema)


def test_review_schema_file_matches_expected_shape(config: StewardConfig) -> None:
    path = review_schema_path(config)
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == [
        "verdict",
        "summary",
        "findings",
        "validation_gaps",
        "remaining_risk",
    ]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["verdict"]["enum"] == ["approve", "block"]
    finding = schema["properties"]["findings"]["items"]
    assert finding["additionalProperties"] is False
    assert finding["properties"]["line"]["type"] == ["integer", "null"]


def test_review_schema_matches_openai_structured_output_subset(
    config: StewardConfig,
) -> None:
    schema = json.loads(review_schema_path(config).read_text(encoding="utf-8"))

    assert_openai_structured_output_schema(schema)


def test_commit_message_schema_matches_openai_structured_output_subset(
    config: StewardConfig,
) -> None:
    schema = json.loads(commit_message_schema_path(config).read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == ["subject", "body"]
    assert schema["additionalProperties"] is False
    assert_openai_structured_output_schema(schema)


def assert_openai_structured_output_schema(schema: dict[str, object]) -> None:
    unsupported_keywords = {
        "allOf",
        "not",
        "dependentRequired",
        "dependentSchemas",
        "if",
        "then",
        "else",
        "patternProperties",
        # Keep schemas compatible with fine-tuned model Structured Outputs too.
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "multipleOf",
        "unevaluatedProperties",
        "propertyNames",
        "minProperties",
        "maxProperties",
        "minItems",
        "maxItems",
        "uniqueItems",
        "contains",
    }
    supported_types = {"string", "number", "boolean", "integer", "object", "array", "null"}
    stats = {
        "properties": 0,
        "enum_values": 0,
        "max_depth": 0,
        "schema_string_length": 0,
        "largest_enum_string_length": 0,
    }

    def visit(node: object, path: str, depth: int) -> None:
        if not isinstance(node, dict):
            return
        stats["max_depth"] = max(stats["max_depth"], depth)
        unsupported = unsupported_keywords & set(node)
        assert not unsupported, f"{path}: unsupported keywords {sorted(unsupported)}"
        if "enum" in node:
            enum = node["enum"]
            assert isinstance(enum, list), f"{path}.enum must be an array"
            stats["enum_values"] += len(enum)
            enum_string_length = 0
            for value in enum:
                if isinstance(value, str):
                    enum_string_length += len(value)
                    stats["schema_string_length"] += len(value)
            stats["largest_enum_string_length"] = max(
                stats["largest_enum_string_length"], enum_string_length
            )
        node_type = node.get("type")
        types = node_type if isinstance(node_type, list) else [node_type]
        assert all(item in supported_types for item in types), (
            f"{path}: unsupported type {node_type!r}"
        )
        if "object" in types:
            properties = node.get("properties")
            assert isinstance(properties, dict), f"{path}: object missing properties"
            assert (
                node.get("additionalProperties") is False
            ), f"{path}: additionalProperties must be false"
            required = node.get("required")
            assert isinstance(required, list), f"{path}: required must be an array"
            assert set(required) == set(properties), (
                f"{path}: required must include exactly every property"
            )
            stats["properties"] += len(properties)
            for key, value in properties.items():
                stats["schema_string_length"] += len(key)
                visit(value, f"{path}.properties.{key}", depth + 1)
        items = node.get("items")
        if isinstance(items, dict):
            visit(items, f"{path}.items", depth + 1)
        for keyword in ("anyOf", "$defs"):
            value = node.get(keyword)
            if isinstance(value, list):
                for index, item in enumerate(value):
                    visit(item, f"{path}.{keyword}[{index}]", depth + 1)
            elif isinstance(value, dict):
                for key, item in value.items():
                    visit(item, f"{path}.{keyword}.{key}", depth + 1)

    visit(schema, "$", 1)
    assert schema.get("type") == "object"
    assert "anyOf" not in schema
    assert stats["properties"] <= 5000
    assert stats["enum_values"] <= 1000
    assert stats["max_depth"] <= 10
    assert stats["schema_string_length"] <= 120_000
    if stats["enum_values"] > 250:
        assert stats["largest_enum_string_length"] <= 15_000


def make_task_stale(store: TaskStore, task_id: str, *, minutes: int = 30) -> None:
    old = utc_now() - timedelta(minutes=minutes)
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task_id)
        assert row is not None
        row.updated_at = old.isoformat()


def test_signal_collector_accepts_providers(config: StewardConfig) -> None:
    class FakeProvider:
        name = "fake"

        def collect(self, _config: StewardConfig) -> ProviderSignalResult:
            return ProviderSignalResult(
                summary="fake signal",
                items=[
                    SignalItem(
                        id="wi-fake-1",
                        provider="fake",
                        kind="fake.item",
                        fingerprint="wi-fake-1",
                        title="Fake signal",
                    )
                ],
            )

    signals = gather_signals(config, providers=[FakeProvider()])

    assert signals.repository == config.github_repository
    assert [item.id for item in signals.items] == ["wi-fake-1"]
    assert signals.summary == "fake signal"
    assert signals.enabled_signals == ["fake"]


def test_signal_fetch_errors_are_not_signal_items(
    config: StewardConfig,
) -> None:
    class FailingProvider:
        name = "codacy"

        def collect(self, _config: StewardConfig) -> ProviderSignalResult:
            raise OSError("dns failed")

    collection = collect_signal_items(config, providers=[FailingProvider()])[0]

    assert collection.error == "dns failed"
    assert collection.items == []


def test_signal_registry_exposes_only_concrete_github_actions_providers() -> None:
    assert "github-actions" not in PROVIDER_TYPES
    assert {
        "github-actions:ci",
        "github-actions:test",
        "github-actions:duvet",
        "github-actions:nightly-ci",
        "github-actions:deploy-demo",
        "github-actions:interop",
        "github-actions:perf",
    }.issubset(PROVIDER_TYPES)


def test_github_actions_interop_signal_filters_workflow(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 123,
                        "workflowName": "Interop",
                        "conclusion": "failure",
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    signals = gather_signals(config, providers=[GitHubActionsInteropProvider()])

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "interop.yml"
    assert args[args.index("--status") + 1] == "failure"
    assert captured["cwd"] == config.repo_root
    assert len(signals.items) == 1
    item = signals.items[0]
    assert item.provider == "github-actions:interop"
    assert item.id.startswith("wi-github-actions-interop-interop-failure-")
    assert item.kind == "github-actions.interop-failure"
    assert item.payload["run_id"] == "123"
    assert item.payload["workflow_name"] == "Interop"
    assert item.payload["conclusion"] == "failure"
    assert item.payload["workflow_file"] == "interop.yml"
    assert item.payload["worker_context"]["recommended_worker"] == "interop-doctor"
    assert item.payload["worker_context"]["recommended_task_kind"] == "interop"
    assert "interop/run-official.sh" in " ".join(
        item.payload["worker_context"]["investigation_steps"]
    )


def test_github_actions_ci_signal_includes_worker_context(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 789,
                        "workflowName": "Per-Commit CI",
                        "conclusion": "failure",
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    signals = gather_signals(config, providers=[GitHubActionsCiProvider()])

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "ci.yml"
    item = signals.items[0]
    assert item.provider == "github-actions:ci"
    assert item.kind == "github-actions.ci-failure"
    assert item.payload["workflow_file"] == "ci.yml"
    context = item.payload["worker_context"]
    assert context["recommended_task_kind"] == "ci"
    assert context["recommended_worker"] == "ci-doctor"
    assert "RFC compliance" in context["workflow_purpose"]
    assert "nix develop -c ./scripts/compliance --ci" in context["local_validation"]


def test_github_actions_perf_signal_is_separate_provider(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 456,
                        "workflowName": "Perf",
                        "conclusion": "failure",
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    signals = gather_signals(config, providers=[GitHubActionsPerfProvider()])

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "perf.yml"
    assert signals.enabled_signals == ["github-actions:perf"]
    assert signals.items[0].provider == "github-actions:perf"
    assert signals.items[0].id.startswith("wi-github-actions-perf-perf-failure-")
    assert signals.items[0].kind == "github-actions.perf-failure"
    assert signals.items[0].payload["run_id"] == "456"
    assert (
        signals.items[0].payload["worker_context"]["workflow_file"]
        == "perf.yml"
    )


def test_codacy_signal_uses_public_issue_search_without_token(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.delenv("CODACY_API_TOKEN", raising=False)
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def read(self) -> bytes:
            return (
                b'{"data":[{"patternInfo":{"id":"Bandit_B310",'
                b'"level":"Warning"},"toolInfo":{"name":"Bandit"},'
                b'"filePath":"steward/src/coquic_steward/web/runtime.py",'
                b'"lineNumber":203}]}'
            )

    def fake_open_codacy_request(request, *, timeout):
        captured["method"] = request.get_method()
        captured["api-token"] = request.headers.get("Api-token")
        captured["url"] = request.full_url
        return FakeResponse()

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        fake_open_codacy_request,
    )

    signals = gather_signals(config, providers=[CodacyProvider()])

    assert captured["method"] == "POST"
    assert captured["api-token"] is None
    assert captured["url"].endswith("/issues/search?limit=12")
    assert len(signals.items) == 1
    item = signals.items[0]
    assert item.id.startswith("wi-codacy-issue-")
    assert item.provider == "codacy"
    assert item.kind == "codacy.issue"
    assert item.severity == "Warning"
    assert item.location == {
        "path": "steward/src/coquic_steward/web/runtime.py",
        "line": 203,
    }
    assert item.payload == {"rule_id": "Bandit_B310", "tool": "Bandit"}


def test_codacy_signal_falls_back_to_public_analysis(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.delenv("CODACY_API_TOKEN", raising=False)
    urls = []

    class SearchFailure:
        def __enter__(self):
            raise OSError("search unavailable")

        def __exit__(self, *_exc):
            return None

    class AnalysisResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def read(self) -> bytes:
            return b'{"data":{"issuesCount":2}}'

    def fake_open_codacy_request(request, *, timeout):
        urls.append(request.full_url)
        if request.full_url.endswith("/issues/search?limit=12"):
            return SearchFailure()
        return AnalysisResponse()

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        fake_open_codacy_request,
    )

    signals = gather_signals(config, providers=[CodacyProvider()])

    assert len(urls) == 2
    assert signals.summary == "Codacy issuesCount=2"
    assert signals.items == []
    assert signals.fetches[0].has_more is True


def test_codacy_signal_uses_tokened_issue_search(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.setenv("CODACY_API_TOKEN", "token")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return None

        def read(self) -> bytes:
            return (
                b'{"data":[{"patternInfo":{"id":"shellcheck_SC2034",'
                b'"level":"Warning"},"toolInfo":{"name":"ShellCheck"},'
                b'"filePath":"scripts/fuzz-targets.sh","lineNumber":9}]}'
            )

    def fake_open_codacy_request(request, *, timeout):
        captured["method"] = request.get_method()
        captured["api-token"] = request.headers.get("Api-token")
        return FakeResponse()

    monkeypatch.setattr(
        "coquic_steward.signals.providers._open_codacy_request",
        fake_open_codacy_request,
    )

    signals = gather_signals(config, providers=[CodacyProvider()])

    assert captured["method"] == "POST"
    assert captured["api-token"] == "token"
    assert len(signals.items) == 1
    item = signals.items[0]
    assert item.id.startswith("wi-codacy-issue-")
    assert item.provider == "codacy"
    assert item.kind == "codacy.issue"
    assert item.severity == "Warning"
    assert item.location == {"path": "scripts/fuzz-targets.sh", "line": 9}
    assert item.payload == {"rule_id": "shellcheck_SC2034", "tool": "ShellCheck"}


def test_codacy_signal_records_error_after_non_2xx_issue_search(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.setenv("CODACY_API_TOKEN", "token")

    class ErrorResponse:
        code = 403
        msg = "Forbidden"
        headers = {}

        def info(self):
            return self.headers

        def close(self) -> None:
            return None

    class FakeHTTPSHandler(BaseHandler):
        def https_open(self, _request):
            return ErrorResponse()

    def fake_codacy_opener() -> OpenerDirector:
        opener = OpenerDirector()
        opener.add_handler(FakeHTTPSHandler())
        opener.add_handler(HTTPDefaultErrorHandler())
        opener.add_handler(HTTPErrorProcessor())
        return opener

    monkeypatch.setattr(
        "coquic_steward.signals.providers._codacy_opener",
        fake_codacy_opener,
    )

    signals = gather_signals(config, providers=[CodacyProvider()])

    assert signals.fetches[0].error == (
        "HTTP Error 403: Forbidden; fallback: HTTP Error 403: Forbidden"
    )
    assert signals.items == []


def test_collect_signal_items_persists_provider_items(config: StewardConfig) -> None:
    class WorkItemProvider:
        name = "codacy"

        def collect(self, _config: StewardConfig) -> ProviderSignalResult:
            return ProviderSignalResult(
                summary="Codacy sampled 1 open finding(s)",
                items=[
                    SignalItem(
                        id="wi-codacy-1",
                        provider="codacy",
                        kind="codacy.issue",
                        fingerprint="wi-codacy-1",
                        title="SC2034 in scripts/fuzz-targets.sh:9",
                        location={"path": "scripts/fuzz-targets.sh", "line": 9},
                        payload={"rule_id": "shellcheck_SC2034"},
                    )
                ],
            )

    collection = collect_signal_items(config, providers=[WorkItemProvider()])[0]

    assert collection.fetch.summary == "Codacy sampled 1 open finding(s)"
    assert [item.id for item in collection.items] == ["wi-codacy-1"]
    assert collection.items[0].source_fetch_id == collection.fetch.id


def test_code_quality_prompt_keeps_worker_inside_patch_boundary(
    config: StewardConfig,
) -> None:
    task = TaskStore(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="CodeQL",
            prompt="fix CodeQL",
            metadata={
                "source_context": {
                    "selected_signal_item_ids": ["wi-codeql-1"],
                    "selected_signal_items": [
                        {
                            "id": "wi-codeql-1",
                            "provider": "code-scanning",
                            "kind": "code-scanning.alert",
                            "payload": {"rule_id": "cpp/use-after-free"},
                            "location": {"path": "src/main.cpp", "line": 12},
                        }
                    ],
                }
            },
        )
    )[0]
    task.worktree_path = config.repo_root

    prompt = render_worker_prompt(task, config)

    assert "Stop at a validated local patch" in prompt
    assert "Do not commit, push, trigger GitHub workflows" in prompt
    assert "Authoritative source context:" in prompt
    assert "cpp/use-after-free" in prompt
    assert "src/main.cpp" in prompt
    assert "single source of truth" in prompt
    assert "Do not fetch a broad or unknown issue list" in prompt


def test_worker_prompt_highlights_workflow_signal_guidance(
    config: StewardConfig,
) -> None:
    task = TaskStore(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.ci,
            worker=WorkerKind.ci_doctor,
            title="Debug failed Test run 100",
            prompt="Debug the selected Test workflow run.",
            metadata={
                "source_context": {
                    "selected_signal_item_ids": ["wi-github-actions-test-1"],
                    "selected_signal_items": [
                        {
                            "id": "wi-github-actions-test-1",
                            "provider": "github-actions:test",
                            "kind": "github-actions.test-failure",
                            "payload": {
                                "run_id": "100",
                                "workflow_file": "test.yml",
                                "worker_context": {
                                    "workflow_file": "test.yml",
                                    "recommended_task_kind": "ci",
                                    "recommended_worker": "ci-doctor",
                                    "workflow_purpose": "Build and unit-test CoQUIC.",
                                    "investigation_steps": [
                                        "Inspect the selected run id for the Build or Test step that failed."
                                    ],
                                    "local_validation": [
                                        "nix develop -c zig build test"
                                    ],
                                    "scope_limits": [
                                        "Commit and push remain Steward integration responsibilities."
                                    ],
                                },
                            },
                        }
                    ],
                }
            },
        )
    )[0]
    task.worktree_path = config.repo_root

    prompt = render_worker_prompt(task, config)

    assert "Selected source guidance:" in prompt
    assert "recommended_worker: ci-doctor" in prompt
    assert "workflow_file: test.yml" in prompt
    assert "nix develop -c zig build test" in prompt
    assert "Authoritative source context:" in prompt


def test_review_verdict_uses_structured_output() -> None:
    approved = parse_review(
        json.dumps(
            {
                "verdict": "approve",
                "summary": "No findings.",
                "findings": [],
                "validation_gaps": [],
                "remaining_risk": "",
            }
        )
    )
    blocked = parse_review(
        json.dumps(
            {
                "verdict": "block",
                "summary": "Unsafe patch.",
                "findings": [
                    {
                        "severity": "high",
                        "title": "Incorrect behavior",
                        "file": "src/main.zig",
                        "line": 10,
                        "detail": "The patch changes unrelated behavior.",
                        "recommendation": "Keep the change scoped.",
                    }
                ],
                "validation_gaps": [],
                "remaining_risk": "Needs another pass.",
            }
        )
    )

    assert approved is not None
    assert review_approved(approved)
    approved_with_gap = approved | {"validation_gaps": ["zig build test was not run"]}
    assert review_approved(approved_with_gap)
    assert blocked is not None
    assert not review_approved(blocked)
    assert parse_review("APPROVE\n\nNo blocking findings.") is None
    assert (
        parse_review(
            json.dumps(
                {
                    "verdict": "block",
                    "summary": "Review not completed.",
                    "findings": [
                        {
                            "severity": "critical",
                            "title": "Invalid premature response",
                            "file": "",
                            "line": None,
                            "detail": (
                                "Internal error: accidentally attempted final "
                                "response prematurely."
                            ),
                            "recommendation": (
                                "Ignore this response; continuing review would "
                                "be required."
                            ),
                        }
                    ],
                    "validation_gaps": ["Review not completed."],
                    "remaining_risk": "Review not completed.",
                }
            )
        )
        is None
    )


def test_worktree_create_and_patch(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktrees = Worktrees(config)
    path, branch = worktrees.create(task)

    (path / "README.md").write_text("changed\n", encoding="utf-8")
    patch = config.patches_dir / "task.patch"
    worktrees.save_patch(path, patch)

    assert path.exists()
    assert branch.startswith("steward/")
    assert "changed" in patch.read_text(encoding="utf-8")
    assert worktrees.has_changes(path)


def test_codex_runner_writes_prompt_and_transcript(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'done\\n' > \"$last\"\n"
        'printf \'{"message":"done"}\\n\'\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert result.completed
    assert result.final_message == "done\n"
    assert result.transcript_path.exists()


def test_codex_runner_reports_missing_codex_executable(config: StewardConfig) -> None:
    config = config.__class__(
        **{**config.__dict__, "codex_bin": "/missing/codex-for-steward-test"}
    )
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert not result.completed
    assert result.exit_code == 127
    assert "unable to start Codex executable" in result.final_message
    transcript = result.transcript_path.read_text(encoding="utf-8")
    event = json.loads(transcript)
    assert event["type"] == "stderr"
    assert "unable to start Codex executable" in event["text"]


def test_executor_no_changes_reaches_terminal_status(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'no changes\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.no_changes
    assert saved.worktree_path is not None
    assert not saved.worktree_path.exists()
    assert any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_executor_heartbeats_active_worker(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.setattr("coquic_steward.execution.executor.WORKER_HEARTBEAT_SECONDS", 0.01)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.update_status(task.id, TaskStatus.running, "started")
    make_task_stale(store, task.id)

    def fake_run() -> WorkerResult:
        import time

        time.sleep(0.05)
        return WorkerResult(
            completed=True,
            command=["fake"],
            cwd=config.repo_root,
            exit_code=0,
            transcript_path=config.transcripts_dir / task.id / "worker" / "codex.jsonl",
            last_message_path=config.transcripts_dir / task.id / "worker" / "last-message.md",
        )

    result = StewardExecutor(config, store)._run_with_heartbeat(task.id, fake_run)

    assert result.completed
    assert store.get(task.id).updated_at > utc_now() - timedelta(minutes=1)


def test_executor_patch_happy_path(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "else\n"
        "  printf 'changed by steward\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert saved.patch_path is not None
    assert "changed by steward" in saved.patch_path.read_text(encoding="utf-8")
    assert saved.worktree_path is not None
    assert not saved.worktree_path.exists()
    assert any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_executor_does_not_clean_external_finished_worktree(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    external = tmp_path / "external-worktree"
    external.mkdir()
    task.worktree_path = external
    store.save(task)
    store.update_status(task.id, TaskStatus.running, "started")

    StewardExecutor(config, store)._finish_task(task.id, TaskStatus.failed, "failed")

    assert external.exists()
    assert not any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_executor_marks_task_validation_running_before_gates(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "else\n"
        "  printf 'changed by steward\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    observed: dict[str, object] = {}

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        current = store.get(task_id)
        iteration = store.get_iteration(task_id, 0)
        validation_event = store.events(task_id)[-1]
        observed["status"] = current.status
        observed["summary"] = current.summary
        observed["task_patch_path"] = current.patch_path
        iteration_patch_text = (
            iteration.patch_path.read_text(encoding="utf-8")
            if iteration.patch_path
            else ""
        )
        observed["iteration_patch_saved"] = bool(iteration.patch_path)
        observed["iteration_patch_has_worker_change"] = (
            "-hello\n+changed by steward\n" in iteration_patch_text
        )
        observed["event_kind"] = validation_event.kind
        observed["event_phase"] = validation_event.data["phase"]

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    assert observed == {
        "status": TaskStatus.running,
        "summary": "validation running: initial",
        "task_patch_path": None,
        "iteration_patch_saved": True,
        "iteration_patch_has_worker_change": True,
        "event_kind": "task.status",
        "event_phase": "validation",
    }


def test_run_validation_applies_configured_timeout(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.core.subprocesses import CommandResult
    from coquic_steward.execution.validation import run_validation

    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(validation_timeout_minutes=2),
        }
    )
    observed: dict[str, object] = {}

    def fake_run_command(command, cwd, *, timeout=None):
        observed["command"] = command
        observed["cwd"] = cwd
        observed["timeout"] = timeout
        return CommandResult(
            args=command,
            cwd=cwd,
            returncode=124,
            stdout="",
            stderr="command timed out",
        )

    monkeypatch.setattr(
        "coquic_steward.execution.validation.run_command", fake_run_command
    )

    result = run_validation(
        config,
        "task-1",
        config.repo_root,
        "slow.txt",
        ["slow-command"],
    )

    assert observed == {
        "command": ["slow-command"],
        "cwd": config.repo_root,
        "timeout": 120,
    }
    assert result.exit_code == 124
    assert not result.passed
    assert "command timed out" in result.output_path.read_text(encoding="utf-8")


def test_executor_retries_invalid_review_output(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  count_file=.review-count\n"
        "  count=0\n"
        '  [ -f "$count_file" ] && count=$(cat "$count_file")\n'
        "  count=$((count + 1))\n"
        '  printf "%s" "$count" > "$count_file"\n'
        '  if [ "$count" = "1" ]; then\n'
        "    printf '{\"verdict\":\"block\",\"summary\":\"Review not completed.\",\"findings\":[{\"severity\":\"critical\",\"title\":\"Invalid premature response\",\"file\":\"\",\"line\":null,\"detail\":\"Internal error: accidentally attempted final response prematurely.\",\"recommendation\":\"Ignore this response; continuing review would be required.\"}],\"validation_gaps\":[\"Review not completed.\"],\"remaining_risk\":\"Review not completed.\"}\\n' > \"$last\"\n"
        "  else\n"
        "    printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  fi\n"
        "else\n"
        "  printf 'changed by steward\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    events = store.events(task.id)

    assert saved.status == TaskStatus.succeeded
    assert (config.transcripts_dir / task.id / "reviewer-0" / "last-message.md").exists()
    assert (
        config.transcripts_dir
        / task.id
        / "reviewer-0-retry-1"
        / "last-message.md"
    ).exists()
    assert [event.kind for event in events].count("review.invalid_output") == 1
    assert [event.kind for event in events].count("review.finished") == 1
    invalid = next(event for event in events if event.kind == "review.invalid_output")
    finished = next(event for event in events if event.kind == "review.finished")
    assert invalid.data["retryable"] is True
    assert invalid.data["review_run"] == 0
    assert finished.data["review_run"] == 1


def test_executor_accepts_approved_review_with_validation_gaps(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok with gap\",\"findings\":[],\"validation_gaps\":[\"shellcheck unavailable\"],\"remaining_risk\":\"low\"}\\n' > \"$last\"\n"
        "else\n"
        "  printf 'changed by steward\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_gates(_config, task_id, cwd, *, label=None):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)

    events = store.events(task.id)
    assert store.get(task.id).status == TaskStatus.succeeded
    assert [event.kind for event in events].count("review.finished") == 1
    assert not any(event.kind == "worker.revision_requested" for event in events)


def test_executor_push_main_queues_integration_task(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "else\n"
        "  printf 'changed by steward\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "integration_mode": IntegrationMode.push_main.value,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="T",
            prompt="P",
        )
    )

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    integration_tasks = [
        item
        for item in store.list_tasks()
        if item.spec.worker == WorkerKind.integration_manager
    ]

    assert saved.status == TaskStatus.integrating
    assert saved.patch_path is not None
    assert len(integration_tasks) == 1
    assert integration_tasks[0].status == TaskStatus.queued
    assert integration_tasks[0].spec.metadata["source_task_id"] == task.id
    assert any(event.kind == "integration.queued" for event in store.events(task.id))


def test_integration_manager_local_only_commits_without_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    subprocess.run(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": True,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fake = tmp_path / "codex"
    args_path = tmp_path / "commit-message-args.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{args_path}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf '%s\\n' '{\"subject\":\"fix(docs): record local integration\",\"body\":\"Record the local integration result without pushing it to the remote.\\n\\nChanged files:\\n- README.md\\n\\nValidation:\\n- fake: passed\\n\\nSource task: local-source\"}' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("local integration\n", encoding="utf-8")
    source.worktree_path = worktree
    source.branch_name = branch
    patch_path = config.patches_dir / f"{source.id}.patch"
    Worktrees(config).save_patch(worktree, patch_path)
    source.patch_path = patch_path
    store.save(source)
    source = store.update_status(source.id, TaskStatus.integrating, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(integration.id)
    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    remote_text = subprocess.run(
        ["git", "show", "origin/main:README.md"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert saved_source.status == TaskStatus.succeeded
    assert saved_integration.status == TaskStatus.succeeded
    assert saved_integration.transcript_path is not None
    transcript = saved_integration.transcript_path.read_text(encoding="utf-8")
    assert "start: Integration run" in transcript
    assert "validation: passed: fake" in transcript
    assert "local_only: external writes disabled" in transcript
    assert "local-only integration commit" in saved_source.summary
    assert remote_text == "hello\n"
    assert any(event.kind == "integration.local_only" for event in store.events(source.id))
    assert any(
        event.kind == "integration.commit_message_generated"
        for event in store.events(source.id)
    )
    assert not any(event.kind == "main.pushed" for event in store.events(source.id))


def test_commit_message_prompt_includes_patch_context(config: StewardConfig) -> None:
    source = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="Fix a focused batch of current Codacy findings",
            prompt="Fix the selected shellcheck finding.",
            metadata={
                "source_context": {
                    "selected_signal_items": [
                        {
                            "id": "wi-codacy-1",
                            "provider": "codacy",
                            "rule_id": "shellcheck_SC2034",
                            "file": "scripts/fuzz-targets.sh",
                            "line": 9,
                        }
                    ]
                }
            },
        )
    )
    validation_output = config.logs_dir / "task-1" / "fake.txt"
    validation = ValidationResult(
        command=["zig", "build", "test"],
        cwd=config.repo_root,
        passed=True,
        exit_code=0,
        output_path=validation_output,
        summary="ok",
    )
    patch_text = """\
diff --git a/scripts/fuzz-targets.sh b/scripts/fuzz-targets.sh
index 1111111..2222222 100644
--- a/scripts/fuzz-targets.sh
+++ b/scripts/fuzz-targets.sh
@@ -1 +1 @@
-old
+new
"""

    prompt = render_commit_message_prompt(
        source, patch_text, ["scripts/fuzz-targets.sh"], [validation]
    )

    assert "integration commit-message writer" in prompt
    assert "Fix the selected shellcheck finding." in prompt
    assert "shellcheck_SC2034" in prompt
    assert "zig" in prompt
    assert "scripts/fuzz-targets.sh" in prompt
    assert patch_text.strip() in prompt


def test_parse_commit_message_rejects_invalid_subject() -> None:
    assert parse_commit_message('{"subject":"fix: update rag","body":"Body"}') == {
        "subject": "fix: update rag",
        "body": "Body",
    }
    assert parse_commit_message('{"subject":"Fix rag","body":"Body"}') is None
    assert (
        parse_commit_message(
            '{"subject":"fix: '
            + ("x" * 80)
            + '","body":"Body"}'
        )
        is None
    )


def test_integration_manager_serializes_push_to_main(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=config.repo_root, check=True)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True)
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": False,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fake = tmp_path / "codex"
    args_path = tmp_path / "commit-message-args.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{args_path}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf '%s\\n' '{\"subject\":\"fix(docs): describe integration output\",\"body\":\"Update the README integration output so the pushed patch describes the resulting repository state.\\n\\nChanged files:\\n- README.md\\n\\nValidation:\\n- fake: passed\\n\\nSource task: source-task\"}' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="T",
            prompt="P",
        )
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("integrated\n", encoding="utf-8")
    source.worktree_path = worktree
    source.branch_name = branch
    patch_path = config.patches_dir / f"{source.id}.patch"
    Worktrees(config).save_patch(worktree, patch_path)
    source.patch_path = patch_path
    store.save(source)
    source = store.update_status(source.id, TaskStatus.integrating, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(integration.id)
    pushed_source = store.get(source.id)
    pushed_integration = store.get(integration.id)
    remote_text = subprocess.run(
        ["git", "show", "origin/main:README.md"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    remote_commit_message = subprocess.run(
        ["git", "log", "-1", "--pretty=%B", "origin/main"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert pushed_source.status == TaskStatus.pushed
    assert pushed_integration.status == TaskStatus.pushed
    assert pushed_integration.worktree_path is not None
    assert not pushed_integration.worktree_path.exists()
    assert remote_text == "integrated\n"
    assert remote_commit_message.startswith("fix(docs): describe integration output\n")
    assert "Source task: source-task" in remote_commit_message
    assert (
        f"Steward-Task: https://coquic.minhuw.dev/steward/tasks/{source.id}"
        in remote_commit_message
    )
    assert "Changed files:\n- README.md" in remote_commit_message
    commit_args = args_path.read_text(encoding="utf-8").splitlines()
    assert commit_args[commit_args.index("--cd") + 1] == str(
        pushed_integration.worktree_path
    )
    assert "--skip-git-repo-check" not in commit_args
    push_log = config.logs_dir / integration.id / "git-push.txt"
    assert push_log.exists()
    assert "$ git push origin HEAD:main" in push_log.read_text(encoding="utf-8")
    assert any(event.kind == "integration.started" for event in store.events(source.id))
    assert any(
        event.kind == "integration.commit_message_generated"
        for event in store.events(source.id)
    )
    assert any(event.kind == "main.pushed" for event in store.events(source.id))


def test_integration_manager_skips_terminal_source_task(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.finish_task(source.id, TaskStatus.failed, "stale active task recovered")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={"source_task_id": source.id},
        )
    )

    assert StewardExecutor(config, store).run_task(integration.id)

    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    assert saved_source.status == TaskStatus.failed
    assert saved_source.summary == "stale active task recovered"
    assert saved_integration.status == TaskStatus.no_changes
    assert "integration source already failed" in saved_integration.summary
    assert any(event.kind == "integration.skipped" for event in store.events(source.id))


def test_integration_manager_fails_on_invalid_commit_message(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=config.repo_root, check=True)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True)
    fake = tmp_path / "codex"
    args_path = tmp_path / "invalid-commit-message-args.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{args_path}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf '{\"subject\":\"not conventional\",\"body\":\"Body\"}\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": False,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.code_quality,
            worker=WorkerKind.code_quality_janitor,
            title="Fix a focused batch of current Codacy findings",
            prompt="P",
        )
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("message failure\n", encoding="utf-8")
    source.worktree_path = worktree
    source.branch_name = branch
    patch_path = config.patches_dir / f"{source.id}.patch"
    Worktrees(config).save_patch(worktree, patch_path)
    source.patch_path = patch_path
    store.save(source)
    source = store.update_status(source.id, TaskStatus.integrating, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )

    def fake_gates(_config, task_id, cwd):
        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert not StewardExecutor(config, store).run_task(integration.id)
    remote_text = subprocess.run(
        ["git", "show", "origin/main:README.md"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    events = store.events(source.id)

    assert saved_source.status == TaskStatus.failed
    assert saved_source.summary == "commit message generation failed"
    assert saved_integration.status == TaskStatus.failed
    assert saved_integration.summary == "commit message generation failed"
    assert remote_text != "message failure\n"
    commit_args = args_path.read_text(encoding="utf-8").splitlines()
    assert commit_args[commit_args.index("--cd") + 1] == str(
        saved_integration.worktree_path
    )
    assert "--skip-git-repo-check" not in commit_args
    assert any(event.kind == "integration.commit_message_failed" for event in events)
    assert not any(event.kind == "main.pushed" for event in events)


def test_integration_conflict_returns_to_worker_then_queues_retry(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=config.repo_root, check=True)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True)
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "resume" ]; then mode=revision; fi\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        'elif [ "$mode" = "revision" ]; then\n'
        "  printf 'current main\\nrepaired change\\n' > README.md\n"
        "  printf 'integration repair done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'old base\\nworker change\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        '  printf \'{"type":"thread.started","thread_id":"worker-thread-1"}\\n\'\n'
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    old_base = Worktrees(config).create(source)[0]
    (old_base / "README.md").write_text("old base\nworker change\n", encoding="utf-8")
    source = store.get(source.id)
    source.worktree_path = old_base
    source.patch_path = config.patches_dir / source.id / "iteration-0.patch"
    source.spec.metadata["worker_thread_id"] = "worker-thread-1"
    Worktrees(config).save_patch(old_base, source.patch_path)
    store.save(source)
    source = store.start_integration(source.id, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(source.patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )
    subprocess.run(
        ["git", "checkout", "main"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    (config.repo_root / "README.md").write_text("current main\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=config.repo_root, check=True)
    subprocess.run(
        ["git", "commit", "-m", "test: move main"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(["git", "push", "origin", "main"], cwd=config.repo_root, check=True)

    def fake_gates(_config, task_id, cwd, *, label=None):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / (label or "integration") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(integration.id)

    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    integration_tasks = [
        item
        for item in store.list_tasks()
        if item.spec.worker == WorkerKind.integration_manager
    ]
    events = store.events(source.id)

    assert saved_integration.status == TaskStatus.blocked
    assert saved_source.status == TaskStatus.integrating
    assert saved_source.patch_path is not None
    assert "repaired change" in saved_source.patch_path.read_text(encoding="utf-8")
    assert len(integration_tasks) == 2
    assert any(item.status == TaskStatus.queued for item in integration_tasks)
    assert any(event.kind == "integration.conflict" for event in events)
    assert any(event.kind == "worker.integration_revision_requested" for event in events)
    assert any(event.kind == "integration.retry_requested" for event in events)
    assert "exec resume --json" in calls.read_text(encoding="utf-8")


def test_integration_conflict_no_changes_marks_source_no_changes(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True)
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'already on main\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    old_base = Worktrees(config).create(source)[0]
    (old_base / "README.md").write_text("old base\nworker change\n", encoding="utf-8")
    source = store.get(source.id)
    source.worktree_path = old_base
    source.patch_path = config.patches_dir / source.id / "iteration-0.patch"
    source.spec.metadata["worker_thread_id"] = "worker-thread-1"
    Worktrees(config).save_patch(old_base, source.patch_path)
    store.save(source)
    source = store.start_integration(source.id, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(source.patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )
    subprocess.run(
        ["git", "checkout", "main"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    (config.repo_root / "README.md").write_text(
        "old base\nworker change\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "README.md"], cwd=config.repo_root, check=True)
    subprocess.run(
        ["git", "commit", "-m", "test: apply equivalent change"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(["git", "push", "origin", "main"], cwd=config.repo_root, check=True)

    assert StewardExecutor(config, store).run_task(integration.id)

    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    integration_tasks = [
        item
        for item in store.list_tasks()
        if item.spec.worker == WorkerKind.integration_manager
    ]
    events = store.events(source.id)

    assert saved_integration.status == TaskStatus.blocked
    assert saved_source.status == TaskStatus.no_changes
    assert saved_source.summary == "worker produced no source changes"
    assert len(integration_tasks) == 1
    assert any(event.kind == "integration.conflict" for event in events)
    assert any(event.kind == "worker.integration_revision_requested" for event in events)
    assert not any(event.kind == "integration.retry_requested" for event in events)
    assert "exec resume --json" in calls.read_text(encoding="utf-8")


def test_integration_validation_failure_returns_to_worker_then_queues_retry(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    subprocess.run(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "resume" ]; then mode=revision; fi\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        'elif [ "$mode" = "revision" ]; then\n'
        "  printf 'validation repaired\\n' > README.md\n"
        "  printf 'integration validation repair done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'needs integration validation repair\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        '  printf \'{"type":"thread.started","thread_id":"worker-thread-1"}\\n\'\n'
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text(
        "needs integration validation repair\n", encoding="utf-8"
    )
    source.worktree_path = worktree
    source.branch_name = branch
    source.patch_path = config.patches_dir / source.id / "iteration-0.patch"
    source.spec.metadata["worker_thread_id"] = "worker-thread-1"
    Worktrees(config).save_patch(worktree, source.patch_path)
    store.save(source)
    source = store.start_integration(source.id, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(source.patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )
    gate_runs = 0

    def fake_gates(_config, task_id, cwd, *, label=None):
        nonlocal gate_runs

        gate_runs += 1
        output = _config.logs_dir / task_id / (label or "integration") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        if label is None:
            output.write_text("failed\n", encoding="utf-8")
            return [
                ValidationResult(
                    command=["fake"],
                    cwd=cwd,
                    passed=False,
                    exit_code=1,
                    output_path=output,
                    summary="integration gate failed",
                )
            ]
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(integration.id)

    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    integration_tasks = [
        item
        for item in store.list_tasks()
        if item.spec.worker == WorkerKind.integration_manager
    ]
    events = store.events(source.id)

    assert saved_integration.status == TaskStatus.blocked
    assert saved_integration.summary == "validation failed after rebase"
    assert saved_source.status == TaskStatus.integrating
    assert saved_source.patch_path is not None
    assert "validation repaired" in saved_source.patch_path.read_text(encoding="utf-8")
    assert len(integration_tasks) == 2
    assert any(item.status == TaskStatus.queued for item in integration_tasks)
    assert any(event.kind == "integration.validation_failed" for event in events)
    assert any(event.kind == "worker.validation_revision_requested" for event in events)
    assert any(event.kind == "integration.retry_requested" for event in events)
    assert "exec resume --json" in calls.read_text(encoding="utf-8")
    assert gate_runs == 2


def test_integration_manager_records_commit_failure_without_crashing(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)], cwd=config.repo_root, check=True
    )
    subprocess.run(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": False,
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf '%s\\n' '{\"subject\":\"fix(docs): update commit failure fixture\",\"body\":\"Update the README fixture before exercising the mocked commit failure.\\n\\nChanged files:\\n- README.md\\n\\nValidation:\\n- fake: passed\\n\\nSource task: failure-source\"}' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("commit hook failure\n", encoding="utf-8")
    source.worktree_path = worktree
    source.branch_name = branch
    patch_path = config.patches_dir / f"{source.id}.patch"
    Worktrees(config).save_patch(worktree, patch_path)
    source.patch_path = patch_path
    store.save(source)
    source = store.update_status(source.id, TaskStatus.integrating, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    def fail_commit(_self, _path, _message, _body=""):
        raise RuntimeError("commit hook failed")

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    monkeypatch.setattr(
        "coquic_steward.execution.worktree.Worktrees.commit_all", fail_commit
    )

    assert not StewardExecutor(config, store).run_task(integration.id)
    failed_source = store.get(source.id)
    failed_integration = store.get(integration.id)

    assert failed_source.status == TaskStatus.failed
    assert failed_source.summary == "commit failed"
    assert failed_integration.status == TaskStatus.failed
    assert failed_integration.transcript_path is not None
    assert "commit_failed: commit hook failed" in failed_integration.transcript_path.read_text(
        encoding="utf-8"
    )
    assert any(
        event.kind == "integration.commit_failed" for event in store.events(source.id)
    )


def test_executor_routes_blocking_review_back_to_worker_session(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "resume" ]; then mode=revision; fi\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  count_file=.review-count\n"
        "  count=0\n"
        '  [ -f "$count_file" ] && count=$(cat "$count_file")\n'
        "  count=$((count + 1))\n"
        '  printf "%s" "$count" > "$count_file"\n'
        '  if [ "$count" = "1" ]; then\n'
        "    printf '{\"verdict\":\"block\",\"summary\":\"needs revision\",\"findings\":[{\"severity\":\"high\",\"title\":\"bad\",\"file\":\"README.md\",\"line\":1,\"detail\":\"bad text\",\"recommendation\":\"fix it\"}],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  else\n"
        "    printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  fi\n"
        'elif [ "$mode" = "revision" ]; then\n'
        f'  printf "%s\\n" "$last" > "{tmp_path / "revision-last-path.txt"}"\n'
        f'  python - <<\'PY\'\nimport sqlite3\nrow = sqlite3.connect("{config.db_path}").execute("select status, transcript_path from tasks where id=?", ("{task.id}",)).fetchone()\nopen("{tmp_path / "revision-active-status.txt"}", "w", encoding="utf-8").write(row[0] if row else "")\nopen("{tmp_path / "revision-active-path.txt"}", "w", encoding="utf-8").write(row[1] if row else "")\nPY\n'
        "  printf 'changed after review\\n' > README.md\n"
        "  printf 'revision done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'changed before review\\n' > README.md\n"
        "  printf 'done\\n' > \"$last\"\n"
        '  printf \'{"type":"thread.started","thread_id":"worker-thread-1"}\\n\'\n'
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    def fake_gates(_config, task_id, cwd):
        from coquic_steward.core.models import ValidationResult

        output = _config.logs_dir / task_id / f"fake-{len(store.get(task_id).validations)}.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert saved.patch_path is not None
    assert "changed after review" in saved.patch_path.read_text(encoding="utf-8")
    assert saved.spec.metadata["worker_thread_id"] == "worker-thread-1"
    call_log = calls.read_text(encoding="utf-8")
    assert "exec resume --json" in call_log
    assert "worker-thread-1" in call_log
    events = store.events(task.id)
    assert [event.kind for event in events].count("review.finished") == 2
    assert any(event.kind == "worker.revision_requested" for event in events)
    assert "worker-revision-1" in (tmp_path / "revision-last-path.txt").read_text(encoding="utf-8")
    assert (
        tmp_path / "revision-active-status.txt"
    ).read_text(encoding="utf-8") == TaskStatus.running.value
    assert "worker-revision-1" in (tmp_path / "revision-active-path.txt").read_text(encoding="utf-8")


def test_executor_persists_iterations_as_first_class_records(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    fake.write_text(
        "#!/bin/sh\n"
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "resume" ]; then mode=revision; fi\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  count_file=.review-count\n"
        "  count=0\n"
        '  [ -f "$count_file" ] && count=$(cat "$count_file")\n'
        "  count=$((count + 1))\n"
        '  printf "%s" "$count" > "$count_file"\n'
        '  if [ "$count" = "1" ]; then\n'
        "    printf '{\"verdict\":\"block\",\"summary\":\"needs revision\",\"findings\":[{\"severity\":\"high\",\"title\":\"bad\",\"file\":\"README.md\",\"line\":1,\"detail\":\"bad\",\"recommendation\":\"fix\"}],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  else\n"
        "    printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  fi\n"
        'elif [ "$mode" = "revision" ]; then\n'
        "  printf 'revision fixed\\n' > README.md\n"
        "  printf 'revision done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'initial change\\n' > README.md\n"
        "  printf 'initial done\\n' > \"$last\"\n"
        '  printf \'{"type":"thread.started","thread_id":"worker-thread-1"}\\n\'\n'
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    gate_runs = 0

    def fake_gates(_config, task_id, cwd, *, label=None):
        nonlocal gate_runs
        from coquic_steward.core.models import ValidationResult

        gate_runs += 1
        output = _config.logs_dir / task_id / (label or "legacy") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"gate {gate_runs}\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"],
                cwd=cwd,
                passed=True,
                exit_code=0,
                output_path=output,
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)

    iterations = store.iterations(task.id)
    assert [item.iteration for item in iterations] == [0, 1]
    assert iterations[0].worker_name == "worker"
    assert iterations[0].reviewer_name == "reviewer-0"
    assert iterations[0].review_json is not None
    assert iterations[0].review_json["verdict"] == "block"
    assert iterations[0].patch_path is not None
    assert iterations[0].patch_path.name == "iteration-0.patch"
    assert iterations[1].worker_name == "worker-revision-1"
    assert iterations[1].reviewer_name == "reviewer-1"
    assert iterations[1].review_json is not None
    assert iterations[1].review_json["verdict"] == "approve"
    assert iterations[1].patch_path is not None
    assert iterations[1].patch_path.name == "iteration-1.patch"

    saved = store.get(task.id)
    assert [validation.iteration for validation in saved.validations] == [0, 1]
    assert saved.validations[0].output_path.parent.name == "iteration-0"
    assert saved.validations[1].output_path.parent.name == "iteration-1"

    with Session(store.engine) as session:
        assert session.query(TaskIterationRow).filter_by(task_id=task.id).count() == 2
        assert {
            row.iteration for row in session.query(ValidationRow).filter_by(task_id=task.id)
        } == {0, 1}


def test_executor_routes_validation_failure_back_to_worker_session(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "resume" ]; then mode=validation; fi\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        'elif [ "$mode" = "validation" ]; then\n'
        f'  printf "%s\\n" "$last" > "{tmp_path / "validation-last-path.txt"}"\n'
        f'  python - <<\'PY\'\nimport sqlite3\nrow = sqlite3.connect("{config.db_path}").execute("select status from tasks where id=?", ("{task.id}",)).fetchone()\nopen("{tmp_path / "validation-active-status.txt"}", "w", encoding="utf-8").write(row[0] if row else "")\nPY\n'
        "  printf 'fixed\\n' > README.md\n"
        "  printf 'validation revision done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'bad\\n' > README.md\n"
        "  printf 'initial done\\n' > \"$last\"\n"
        '  printf \'{"type":"thread.started","thread_id":"worker-thread-1"}\\n\'\n'
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    gate_runs = 0

    def fake_gates(_config, task_id, cwd):
        nonlocal gate_runs
        from coquic_steward.core.models import ValidationResult

        gate_runs += 1
        output = _config.logs_dir / task_id / f"validation-{gate_runs}.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        passed = gate_runs > 1
        output.write_text("ok\n" if passed else "validation failed\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-validation"],
                cwd=cwd,
                passed=passed,
                exit_code=0 if passed else 1,
                output_path=output,
                summary="ok" if passed else "validation failed",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert saved.patch_path is not None
    assert "fixed" in saved.patch_path.read_text(encoding="utf-8")
    call_log = calls.read_text(encoding="utf-8")
    assert "exec resume --json" in call_log
    assert "worker-thread-1" in call_log
    assert "worker-validation-revision-1" in (
        tmp_path / "validation-last-path.txt"
    ).read_text(encoding="utf-8")
    assert (
        tmp_path / "validation-active-status.txt"
    ).read_text(encoding="utf-8") == TaskStatus.running.value
    events = store.events(task.id)
    assert any(event.kind == "validation.failed" for event in events)
    assert any(
        event.kind == "worker.validation_revision_requested" for event in events
    )
    iterations = store.iterations(task.id)
    assert iterations[0].patch_path is not None
    assert "bad" in iterations[0].patch_path.read_text(encoding="utf-8")
    assert iterations[1].patch_path is not None
    assert "fixed" in iterations[1].patch_path.read_text(encoding="utf-8")


def test_executor_uses_shared_revision_counter_for_validation_and_review(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        "mode=worker\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "resume" ]; then mode=revision; fi\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        '  case "$last" in */reviewer-*) mode=review;; esac\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "review" ]; then\n'
        "  count_file=.review-count\n"
        "  count=0\n"
        '  [ -f "$count_file" ] && count=$(cat "$count_file")\n'
        "  count=$((count + 1))\n"
        '  printf "%s" "$count" > "$count_file"\n'
        '  if [ "$count" = "1" ]; then\n'
        "    printf '{\"verdict\":\"block\",\"summary\":\"needs review revision\",\"findings\":[{\"severity\":\"high\",\"title\":\"bad\",\"file\":\"README.md\",\"line\":1,\"detail\":\"bad\",\"recommendation\":\"fix\"}],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  else\n"
        "    printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        "  fi\n"
        'elif [ "$mode" = "revision" ]; then\n'
        "  case \"$last\" in\n"
        "    */worker-validation-revision-1/*) printf 'validation fixed\\n' > README.md ;;\n"
        "    */worker-revision-2/*) printf 'review fixed\\n' > README.md ;;\n"
        "  esac\n"
        "  printf 'revision done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'bad\\n' > README.md\n"
        "  printf 'initial done\\n' > \"$last\"\n"
        '  printf \'{"type":"thread.started","thread_id":"worker-thread-1"}\\n\'\n'
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    gate_runs = 0

    def fake_gates(_config, task_id, cwd):
        nonlocal gate_runs
        from coquic_steward.core.models import ValidationResult

        gate_runs += 1
        output = _config.logs_dir / task_id / f"validation-{gate_runs}.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        passed = gate_runs > 1
        output.write_text("ok\n" if passed else "validation failed\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-validation"],
                cwd=cwd,
                passed=passed,
                exit_code=0 if passed else 1,
                output_path=output,
                summary="ok" if passed else "validation failed",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert saved.patch_path is not None
    assert "review fixed" in saved.patch_path.read_text(encoding="utf-8")
    call_log = calls.read_text(encoding="utf-8")
    assert "worker-validation-revision-1" in call_log
    assert "worker-revision-2" in call_log
    assert "worker-revision-1" not in call_log


def test_cli_enqueue_and_status(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    runner = CliRunner()

    result = runner.invoke(app, ["enqueue", "custom", "demo", "--prompt", "hello"])
    assert result.exit_code == 0
    task_id = result.output.strip().split()[-1]

    status = runner.invoke(app, ["status"])
    assert status.exit_code == 0
    assert task_id in status.output


def test_cli_publish_public_state_writes_output(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    store = TaskStore(load_config().db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    output = repo / "status.json"

    result = CliRunner().invoke(
        app,
        ["publish-public-state", "--output", str(output)],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["tasks"][0]["id"] == task.id


def test_cli_daemon_starts_web_runtime_for_forever_mode(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    started = []
    captured = {}

    class FakeRuntime:
        api_url = "http://127.0.0.1:8765"
        ui_url = "http://127.0.0.1:3000"

        def __init__(
            self,
            *,
            log_dir: Path | None = None,
            expected_state_dir: Path | None = None,
        ):
            started.append(f"log_dir={log_dir.name if log_dir else '-'}")
            captured["expected_state_dir"] = expected_state_dir

        def __enter__(self):
            started.append("enter")
            return self

        def __exit__(self, *_exc):
            started.append("exit")

    def fake_run_forever(self) -> None:
        started.append("daemon")

    monkeypatch.setattr("coquic_steward.cli.StewardWebRuntime", FakeRuntime)
    monkeypatch.setattr(
        "coquic_steward.cli.StewardDaemon.run_forever", fake_run_forever
    )

    result = CliRunner().invoke(app, ["daemon"])

    assert result.exit_code == 0
    assert started == ["log_dir=logs", "enter", "daemon", "exit"]
    assert captured["expected_state_dir"] == load_config().state_dir
    assert "Steward Web UI: http://127.0.0.1:3000" in result.output


def test_cli_daemon_can_run_without_web_runtime(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    started = []

    class FakeRuntime:
        def __enter__(self):
            raise AssertionError("web runtime should not start")

    def fake_run_forever(self) -> None:
        started.append("daemon")

    monkeypatch.setattr("coquic_steward.cli.StewardWebRuntime", FakeRuntime)
    monkeypatch.setattr(
        "coquic_steward.cli.StewardDaemon.run_forever", fake_run_forever
    )

    result = CliRunner().invoke(app, ["daemon", "--no-web"])

    assert result.exit_code == 0
    assert started == ["daemon"]


def test_cli_daemon_once_does_not_start_web_runtime(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)

    class FakeRuntime:
        def __enter__(self):
            raise AssertionError("web runtime should not start")

    monkeypatch.setattr("coquic_steward.cli.StewardWebRuntime", FakeRuntime)

    result = CliRunner().invoke(app, ["daemon", "--once", "--no-plan", "--no-dispatch"])

    assert result.exit_code == 0
    assert "TickResult" in result.output


def test_cli_daemon_exits_when_push_preflight_fails(
    repo: Path, coquic_home: Path, monkeypatch
) -> None:
    monkeypatch.chdir(repo)
    coquic_home.mkdir(parents=True, exist_ok=True)
    (coquic_home / "steward.toml").write_text(
        """
[steward]
integration_mode = "push-main"
git_remote = "origin"
main_branch = "main"
github_repository = "minhuw/coquic"
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["daemon", "--once", "--no-plan", "--no-dispatch"])

    assert result.exit_code == 1
    assert "remote push preflight failed" in result.output
    assert "TickResult" not in result.output


def test_web_runtime_rejects_api_without_signal_items_v2(monkeypatch) -> None:
    from coquic_steward.web import runtime

    def fake_read_url(url: str) -> str | None:
        return "ok" if url.endswith("/healthz") else None

    def fake_read_json(url: str) -> object:
        assert url.endswith("/api/runtime")
        return {"api": "coquic-steward", "features": ["line-tail", "signal-inbox"]}

    monkeypatch.setattr(runtime, "_read_url", fake_read_url)
    monkeypatch.setattr(runtime, "_read_json", fake_read_json)

    assert runtime._api_ready("http://127.0.0.1:8765") is False


def test_web_runtime_rejects_api_with_different_state_dir(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.web import runtime

    expected = tmp_path / "expected" / "steward"
    actual = tmp_path / "actual" / "steward"

    def fake_read_url(url: str) -> str | None:
        return "ok" if url.endswith("/healthz") else None

    def fake_read_json(url: str) -> object:
        assert url.endswith("/api/runtime")
        return {
            "api": "coquic-steward",
            "state_dir": str(actual),
            "features": ["line-tail", "signal-inbox", "signal-items-v2"],
        }

    monkeypatch.setattr(runtime, "_read_url", fake_read_url)
    monkeypatch.setattr(runtime, "_read_json", fake_read_json)

    assert (
        runtime._api_ready(
            "http://127.0.0.1:8765", expected_state_dir=expected
        )
        is False
    )
    assert "running state_dir=" in runtime._api_state_detail(
        "http://127.0.0.1:8765", expected_state_dir=expected
    )


def test_web_runtime_read_url_rejects_non_loopback_urls(monkeypatch) -> None:
    from coquic_steward.web import runtime

    def fail_connection(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("remote URL should not be opened")

    monkeypatch.setattr(runtime.http.client, "HTTPConnection", fail_connection)

    assert runtime._read_url("file:///etc/passwd") is None
    assert runtime._read_url("https://127.0.0.1:8765/healthz") is None
    assert runtime._read_url("http://example.com/healthz") is None


def test_web_runtime_read_url_opens_loopback_http(monkeypatch) -> None:
    from coquic_steward.web import runtime

    requests: list[tuple[str, int | None, str]] = []

    class FakeResponse:
        status = 200

        def read(self, _size: int) -> bytes:
            return b"ok"

    class FakeConnection:
        def __init__(
            self, host: str, port: int | None = None, *, timeout: int | None = None
        ) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout

        def request(self, method: str, path: str) -> None:
            assert method == "GET"
            assert self.timeout == 1
            requests.append((self.host, self.port, path))

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(runtime.http.client, "HTTPConnection", FakeConnection)

    assert runtime._read_url("http://127.0.0.1:8765/healthz?ready=1") == "ok"
    assert requests == [("127.0.0.1", 8765, "/healthz?ready=1")]


def test_web_runtime_reports_incompatible_running_api(tmp_path: Path, monkeypatch) -> None:
    from coquic_steward.web import runtime

    monkeypatch.setattr(runtime, "_api_ready", lambda _url, **_kwargs: False)
    monkeypatch.setattr(runtime, "_api_responding", lambda _url: True)

    with pytest.raises(RuntimeError, match="incompatible Steward API"):
        runtime.StewardWebRuntime(web_ui_dir=tmp_path).start()


def test_web_runtime_resolves_executable_before_spawn(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.web import runtime

    executable = tmp_path / "steward-test-command"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 123

        def poll(self) -> int | None:
            return None

    def fake_process(command: runtime._ResolvedCommand, **kwargs: object) -> FakeProcess:
        captured["args"] = list(command.args)
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(runtime, "_TrustedProcess", fake_process)

    process = runtime._popen(
        ["steward-test-command", "run", "dev"],
        env={"PATH": str(tmp_path)},
    )

    assert isinstance(process, FakeProcess)
    assert captured["args"] == [str(executable), "run", "dev"]
    assert captured["kwargs"] is not None
    assert captured["kwargs"]["env"] == {"PATH": str(tmp_path)}


def test_web_runtime_resolves_relative_path_entries_from_child_cwd(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.web import runtime

    parent_executable = tmp_path / "steward-test-command"
    parent_executable.write_text("#!/bin/sh\n", encoding="utf-8")
    parent_executable.chmod(0o755)
    child_cwd = tmp_path / "web-ui"
    child_cwd.mkdir()
    cwd_executable = child_cwd / "steward-test-command"
    cwd_executable.write_text("#!/bin/sh\n", encoding="utf-8")
    cwd_executable.chmod(0o755)
    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 123

        def poll(self) -> int | None:
            return None

    def fake_process(command: runtime._ResolvedCommand, **kwargs: object) -> FakeProcess:
        captured["args"] = list(command.args)
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime, "_TrustedProcess", fake_process)

    process = runtime._popen(
        ["steward-test-command", "run", "dev"],
        cwd=child_cwd,
        env={"PATH": "."},
    )

    assert isinstance(process, FakeProcess)
    assert captured["args"] == [str(cwd_executable), "run", "dev"]
    assert captured["args"] != [str(parent_executable), "run", "dev"]
    assert captured["kwargs"] is not None
    assert captured["kwargs"]["cwd"] == child_cwd


def test_web_runtime_preserves_symlinked_executable_path(tmp_path: Path) -> None:
    from coquic_steward.web import runtime

    target = tmp_path / "python-target"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    executable = tmp_path / "python-link"
    executable.symlink_to(target)

    command = runtime._resolve_command([str(executable), "-m", "uvicorn"])

    assert command.args == (str(executable), "-m", "uvicorn")


def test_web_runtime_rejects_empty_command_argument() -> None:
    from coquic_steward.web import runtime

    with pytest.raises(RuntimeError, match="non-empty strings"):
        runtime._resolve_command(["npm", ""])


def test_web_runtime_clears_stale_next_cache_before_starting_ui(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.web import runtime

    web_ui_dir = tmp_path / "web-ui"
    stale_file = web_ui_dir / ".next" / "dev" / "cache" / "turbopack" / "stale.sst"
    stale_file.parent.mkdir(parents=True)
    stale_file.write_text("stale", encoding="utf-8")
    started: list[bool] = []

    class FakeProcess:
        def poll(self) -> int | None:
            return None

    def fake_popen(*_args, **_kwargs):
        started.append(True)
        assert not (web_ui_dir / ".next").exists()
        return FakeProcess()

    monkeypatch.setattr(runtime, "_api_ready", lambda _url, **_kwargs: True)
    monkeypatch.setattr(runtime, "_ui_ready", lambda _url: bool(started))
    monkeypatch.setattr(runtime, "_popen", fake_popen)

    runtime.StewardWebRuntime(web_ui_dir=web_ui_dir).start()

    assert started == [True]
    assert not stale_file.exists()


def test_cli_daemon_refuses_second_instance(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)

    with acquire_daemon_lock(config):
        result = CliRunner().invoke(
            app, ["daemon", "--once", "--no-plan", "--no-dispatch"]
        )

    assert result.exit_code == 1
    assert "Steward daemon already running" in result.output
    assert str(config.state_dir / "daemon.lock") in result.output


def test_web_health_and_dashboard(config: StewardConfig, monkeypatch) -> None:
    monkeypatch.chdir(config.repo_root)
    task, _ = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    assert client.get("/healthz").text == "ok"
    features = client.get("/api/runtime").json()["features"]
    assert "line-tail" in features
    assert "signal-inbox" in features
    assert "signal-items-v2" in features
    assert "scheduler-v1" in features
    dashboard = client.get("/", follow_redirects=False)
    assert dashboard.status_code == 307
    assert dashboard.headers["location"] == "http://127.0.0.1:3000"
    payload = client.get("/api/state").json()
    assert payload["tasks"][0]["spec"]["id"] == task.id
    assert payload["kinds"]
    assert payload["workers"]
    assert payload["scheduler"]["source_queued"] == 1
    assert payload["scheduler"]["source_capacity"] == config.limits.max_active_tasks
    assert [provider["provider"] for provider in payload["scheduler"]["providers"]] == [
        "github-actions:ci",
        "github-actions:test",
        "github-actions:duvet",
        "github-actions:nightly-ci",
        "github-actions:deploy-demo",
        "github-actions:interop",
        "github-actions:perf",
        "code-scanning",
        "codacy",
    ]
    assert payload["config"]["coquic_home"] == str(config.coquic_home)
    assert payload["config"]["codex_sandbox"] == config.codex_sandbox
    assert payload["config"]["limits"]["max_active_tasks"] == config.limits.max_active_tasks
    assert payload["config"]["signal_providers"]["codacy"]["max_items"] == 12


def test_web_state_returns_signal_inbox_without_fetching(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    item, _ = store.add_signal_item(
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Codacy issue",
            summary="Codacy issuesCount=2",
        )
    )
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            item_count=1,
            new_item_count=1,
            summary="Codacy issuesCount=2",
        )
    )
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    started = time.monotonic()
    payload = client.get("/api/state").json()
    elapsed = time.monotonic() - started

    assert elapsed < 0.1
    assert payload["signals"]["repository"] == config.github_repository
    assert payload["signals"]["summary"] == "Codacy issuesCount=2"
    assert payload["signals"]["items"][0]["id"] == item.id
    assert payload["signal_inbox"]["items"][0]["id"] == item.id
    assert payload["signal_inbox"]["fetch_runs"][0]["item_count"] == 1


def test_web_state_keeps_signal_fetch_errors_separate_from_items(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.error,
            summary="dns failed",
            error="dns failed",
        )
    )
    app = create_app()
    from fastapi.testclient import TestClient

    payload = TestClient(app).get("/api/state").json()

    assert payload["signal_inbox"]["items"] == []
    assert payload["signal_inbox"]["fetch_runs"][0]["error"] == "dns failed"


def test_web_serves_planner_run_list_and_lazy_artifact(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    older_id = "planner-task-20260618110000-abcdef12"
    latest_id = "planner-task-20260618120000-abcdef12"
    for planner_id, prompt_text, transcript_text in [
        (older_id, "older prompt\n", '{"message":"older result"}\n'),
        (latest_id, "planner prompt\n", '{"message":"planner result"}\n'),
    ]:
        prompt = config.prompts_dir / planner_id / "planner.md"
        transcript = config.transcripts_dir / planner_id / "planner" / "codex.jsonl"
        prompt.parent.mkdir(parents=True, exist_ok=True)
        transcript.parent.mkdir(parents=True, exist_ok=True)
        prompt.write_text(prompt_text, encoding="utf-8")
        transcript.write_text(transcript_text, encoding="utf-8")
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.get("/api/planner/runs")

    assert response.status_code == 200
    payload = response.json()
    assert [run["run_id"] for run in payload["runs"]] == [latest_id, older_id]
    assert payload["total"] == 2
    assert payload["limit"] == 40
    assert payload["offset"] == 0
    assert "prompt" not in payload["runs"][0]
    assert "transcript" not in payload["runs"][0]
    assert payload["runs"][0]["prompt_path"].endswith("/planner.md")
    assert payload["runs"][0]["transcript_path"].endswith("/codex.jsonl")
    assert payload["runs"][0]["prompt_bytes"] == len("planner prompt\n")
    assert payload["runs"][0]["transcript_bytes"] == len('{"message":"planner result"}\n')
    paged = client.get("/api/planner/runs?limit=1&offset=1").json()
    assert [run["run_id"] for run in paged["runs"]] == [older_id]
    assert paged["total"] == 2
    assert paged["limit"] == 1
    assert paged["offset"] == 1

    artifact = client.get(f"/api/planner/runs/{latest_id}").json()

    assert artifact["run_id"] == latest_id
    assert artifact["prompt"] == "planner prompt\n"
    assert artifact["transcript"] == '{"message":"planner result"}\n'
    assert artifact["diagnostics"]["status"] == "missing_last_message"
    assert artifact["diagnostics"]["last_message_present"] is False


def test_web_create_task_and_json(config: StewardConfig, monkeypatch) -> None:
    monkeypatch.chdir(config.repo_root)
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post(
        "/api/tasks",
        json={
            "title": "Web task",
            "kind": "custom",
            "worker": "custom",
            "prompt": "from web",
        },
    )
    assert response.status_code == 200
    assert response.json()["created"] is True

    payload = client.get("/api/state").json()
    assert payload["tasks"][0]["spec"]["title"] == "Web task"
    task_id = payload["tasks"][0]["spec"]["id"]
    detail = client.get(f"/api/tasks/{task_id}").json()
    assert detail["task"]["spec"]["prompt"] == "from web"
    assert detail["files"]["patch"] is None


def test_web_run_task_action(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'no changes\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr("coquic_steward.web.app.load_config", lambda: config)
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post(f"/api/tasks/{task.id}/run")
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert store.get(task.id).status == TaskStatus.no_changes
    assert "no changes" in client.get(f"/api/tasks/{task.id}/files/last-message").text


def test_web_run_task_action_respects_daemon_lock(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    with acquire_daemon_lock(config):
        response = client.post(f"/api/tasks/{task.id}/run")

    assert response.status_code == 409
    assert store.get(task.id).status == TaskStatus.queued


def test_web_tick_action_requests_scheduler_wakeup(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    with acquire_daemon_lock(config):
        response = client.post(
            "/api/actions/tick", json={"plan": False, "dispatch": False}
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["wakeup"]["reason"] == "scheduler.manual"
    assert "state" not in payload
    assert "scheduler" in payload
    wakeup = store.pending_wakeups()[0]
    assert wakeup.reason == "scheduler.manual"
    assert wakeup.data["plan"] is False
    assert wakeup.data["dispatch"] is False


def test_web_force_signal_fetch_requests_provider_wakeup(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post("/api/actions/fetch-signals", json={"providers": ["codacy"]})

    assert response.status_code == 200
    payload = response.json()
    assert payload["wakeup"]["reason"] == "signal.fetch"
    assert "state" not in payload
    assert "scheduler" in payload
    wakeup = store.pending_wakeups()[0]
    assert wakeup.reason == "signal.fetch"
    assert wakeup.data["providers"] == ["codacy"]


def test_web_validation_log_endpoint(config: StewardConfig, monkeypatch) -> None:
    from coquic_steward.core.models import ValidationResult

    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    log = config.logs_dir / task.id / "gate.txt"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("gate output\n", encoding="utf-8")
    task.validations.append(
        ValidationResult(
            command=["gate"],
            cwd=config.repo_root,
            passed=True,
            exit_code=0,
            output_path=log,
        )
    )
    store.save(task)
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.get(f"/api/tasks/{task.id}/validations/0")
    assert response.status_code == 200
    assert response.text == "gate output\n"


def test_web_serves_latest_review_transcript(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    older = config.transcripts_dir / task.id / "reviewer-0" / "codex.jsonl"
    newer = config.transcripts_dir / task.id / "reviewer-1" / "codex.jsonl"
    older.parent.mkdir(parents=True, exist_ok=True)
    newer.parent.mkdir(parents=True, exist_ok=True)
    older.write_text('{"message":"old review"}\n', encoding="utf-8")
    newer.write_text('{"message":"new review"}\n', encoding="utf-8")
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    detail = client.get(f"/api/tasks/{task.id}").json()
    response = client.get(f"/api/tasks/{task.id}/files/review-transcript")

    assert detail["files"]["review_transcript"].endswith("/reviewer-1/codex.jsonl")
    assert response.status_code == 200
    assert response.text == '{"message":"new review"}\n'


def test_web_task_detail_returns_attempt_stack(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.core.models import ValidationResult

    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worker = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    reviewer = config.transcripts_dir / task.id / "reviewer-0" / "codex.jsonl"
    revision = config.transcripts_dir / task.id / "worker-revision-1" / "codex.jsonl"
    integration_revision = (
        config.transcripts_dir
        / task.id
        / "worker-integration-revision-2"
        / "codex.jsonl"
    )
    for path, text in [(worker, '{"message":"worker"}\n')]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    log = config.logs_dir / task.id / "gate.txt"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("gate output\n", encoding="utf-8")
    task.validations.append(
        ValidationResult(
            command=["gate"],
            cwd=config.repo_root,
            passed=True,
            exit_code=0,
            output_path=log,
        )
    )
    store.save(task)
    for path, text in [
        (reviewer, '{"message":"reviewer"}\n'),
        (revision, '{"message":"revision"}\n'),
        (integration_revision, '{"message":"integration revision"}\n'),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    detail = client.get(f"/api/tasks/{task.id}").json()
    response = client.get(f"/api/tasks/{task.id}/runs/worker-revision-1/transcript")
    integration_response = client.get(
        f"/api/tasks/{task.id}/runs/worker-integration-revision-2/transcript"
    )
    unsafe = client.get(f"/api/tasks/{task.id}/runs/../worker/transcript")

    assert [attempt["attempt"] for attempt in detail["attempts"]] == [0, 1, 2]
    assert detail["attempts"][0]["worker"]["name"] == "worker"
    assert detail["attempts"][0]["reviewer"]["name"] == "reviewer-0"
    assert detail["attempts"][1]["worker"]["name"] == "worker-revision-1"
    assert detail["attempts"][2]["worker"]["name"] == "worker-integration-revision-2"
    assert detail["attempts"][0]["validations"][0]["index"] == 0
    assert response.status_code == 200
    assert response.text == '{"message":"revision"}\n'
    assert integration_response.status_code == 200
    assert integration_response.text == '{"message":"integration revision"}\n'
    assert unsafe.status_code in {400, 404}


def test_web_run_transcript_can_return_full_text(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    transcript = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(
        '{"type":"thread.started","thread_id":"t"}\n'
        + '{"type":"item.completed","item":{"id":"big","type":"command_execution","aggregated_output":"'
        + ("x" * (TEXT_TAIL_BYTES + 1024))
        + '"}}\n',
        encoding="utf-8",
    )
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    tail_response = client.get(f"/api/tasks/{task.id}/runs/worker/transcript")
    full_response = client.get(f"/api/tasks/{task.id}/runs/worker/transcript?full=1")

    assert tail_response.status_code == 200
    assert full_response.status_code == 200
    assert len(tail_response.text) < len(full_response.text)
    assert full_response.text == transcript.read_text(encoding="utf-8")


def test_web_run_transcript_window_returns_metadata(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    transcript = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text("one\n" + ("two\n" * 100) + "three\n", encoding="utf-8")
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    latest = client.get(f"/api/tasks/{task.id}/runs/worker/transcript?window=1&limit=20")
    latest_payload = latest.json()
    earlier = client.get(
        f"/api/tasks/{task.id}/runs/worker/transcript"
        f"?window=1&offset={max(0, latest_payload['start'] - 20)}&limit=20"
    )
    earlier_payload = earlier.json()

    assert latest.status_code == 200
    assert latest_payload["size"] == transcript.stat().st_size
    assert latest_payload["end"] == latest_payload["size"]
    assert latest_payload["has_before"] is True
    assert latest_payload["has_after"] is False
    assert latest_payload["text"].endswith("three\n")
    assert earlier.status_code == 200
    assert earlier_payload["end"] <= latest_payload["start"]
    assert earlier_payload["has_before"] is True
    assert earlier_payload["has_after"] is True


def test_web_task_detail_prefers_database_iterations(
    config: StewardConfig, monkeypatch
) -> None:
    from coquic_steward.core.models import WorkerResult

    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worker = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    worker.parent.mkdir(parents=True, exist_ok=True)
    worker.write_text('{"message":"worker"}\n', encoding="utf-8")
    last = worker.parent / "last-message.md"
    last.write_text("done\n", encoding="utf-8")
    patch = config.patches_dir / task.id / "iteration-0.patch"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_text("diff --git a/README.md b/README.md\n", encoding="utf-8")
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=worker,
        worker_last_message_path=last,
    )
    store.finish_iteration_worker(
        task.id,
        0,
        WorkerResult(
            completed=True,
            command=["codex"],
            cwd=config.repo_root,
            exit_code=0,
            prompt_path=config.prompts_dir / task.id / "worker.md",
            transcript_path=worker,
            last_message_path=last,
            final_message="done",
        ),
    )
    store.record_iteration_patch(task.id, 0, patch)
    store.record_iteration_review(
        task.id,
        0,
        WorkerResult(
            completed=True,
            command=["codex", "review"],
            cwd=config.repo_root,
            exit_code=0,
            prompt_path=config.prompts_dir / task.id / "reviewer-0.md",
            transcript_path=config.transcripts_dir / task.id / "reviewer-0" / "codex.jsonl",
            last_message_path=config.transcripts_dir / task.id / "reviewer-0" / "last-message.md",
            final_message="{}",
        ),
        reviewer_name="reviewer-0",
        review_run=0,
        review={
            "verdict": "approve",
            "summary": "ok",
            "findings": [],
            "validation_gaps": [],
            "remaining_risk": "",
        },
    )
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    detail = client.get(f"/api/tasks/{task.id}").json()
    patch_response = client.get(f"/api/tasks/{task.id}/iterations/0/patch")

    assert detail["attempts"][0]["review"]["verdict"] == "approve"
    assert detail["attempts"][0]["patch_path"].endswith("iteration-0.patch")
    assert patch_response.status_code == 200
    assert patch_response.text == "diff --git a/README.md b/README.md\n"


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


def test_web_task_detail_falls_back_to_live_reviewer_file_for_iteration(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worker = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    reviewer = config.transcripts_dir / task.id / "reviewer-0" / "codex.jsonl"
    for path, text in [
        (worker, '{"message":"worker"}\n'),
        (reviewer, '{"message":"live review"}\n'),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=worker,
        worker_last_message_path=worker.parent / "last-message.md",
    )
    app = create_app()
    from fastapi.testclient import TestClient

    detail = TestClient(app).get(f"/api/tasks/{task.id}").json()

    assert detail["attempts"][0]["reviewer"]["name"] == "reviewer-0"
    assert detail["attempts"][0]["reviewer"]["transcript_path"].endswith(
        "reviewer-0/codex.jsonl"
    )


def test_web_task_detail_uses_latest_reviewer_retry(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worker = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    reviewer = config.transcripts_dir / task.id / "reviewer-0" / "codex.jsonl"
    retry = config.transcripts_dir / task.id / "reviewer-0-retry-1" / "codex.jsonl"
    for path, text in [
        (worker, '{"message":"worker"}\n'),
        (reviewer, '{"message":"invalid review"}\n'),
        (retry, '{"message":"retry review"}\n'),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    app = create_app()
    from fastapi.testclient import TestClient

    detail = TestClient(app).get(f"/api/tasks/{task.id}").json()

    assert detail["attempts"][0]["reviewer"]["name"] == "reviewer-0-retry-1"
    assert detail["attempts"][0]["reviewer"]["review_run"] == 1


def test_web_task_detail_groups_validation_revision_attempt(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worker = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    revision = (
        config.transcripts_dir
        / task.id
        / "worker-validation-revision-1"
        / "codex.jsonl"
    )
    for path, text in [
        (worker, '{"message":"worker"}\n'),
        (revision, '{"message":"validation revision"}\n'),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    app = create_app()
    from fastapi.testclient import TestClient

    detail = TestClient(app).get(f"/api/tasks/{task.id}").json()

    assert [attempt["label"] for attempt in detail["attempts"]] == [
        "Initial attempt",
        "Validation revision 1",
    ]
    assert detail["attempts"][1]["worker"]["name"] == "worker-validation-revision-1"


def test_web_task_detail_returns_pushed_commit_url(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.add_event(task.id, "main.pushed", "0123456789abcdef")
    app = create_app()
    from fastapi.testclient import TestClient

    response = TestClient(app).get(f"/api/tasks/{task.id}")

    assert response.status_code == 200
    remote = response.json()["remote"]
    assert remote["commit"] == "0123456789abcdef"
    assert (
        remote["commit_url"]
        == "https://github.com/minhuw/coquic/commit/0123456789abcdef"
    )


def test_web_state_returns_integration_summary(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="Source", prompt="P")
    )
    patch = config.patches_dir / f"{source.id}.patch"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_text("diff\n", encoding="utf-8")
    source.patch_path = patch
    store.save(source)
    source = store.update_status(source.id, TaskStatus.integrating, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate Source",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(patch),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )
    store.add_event(
        source.id,
        "integration.queued",
        integration.id,
        {"integration_task_id": integration.id},
    )
    store.add_event(integration.id, "main.pushed", "0123456789abcdef")
    store.add_event(source.id, "main.pushed", "0123456789abcdef")
    app = create_app()
    from fastapi.testclient import TestClient

    payload = TestClient(app).get("/api/state").json()

    assert payload["integration"]["queue"][0]["task_id"] == integration.id
    assert payload["integration"]["queue"][0]["source_task_id"] == source.id
    assert payload["integration"]["queue"][0]["source_patch_path"] == str(patch)
    assert payload["integration"]["runs"][0]["task_id"] == integration.id
    assert payload["integration"]["runs"][0]["source_task_id"] == source.id
    assert len(payload["integration"]["commits"]) == 1
    assert payload["integration"]["commits"][0]["task_id"] == source.id
    assert payload["integration"]["commits"][0]["commit"] == "0123456789abcdef"
    assert (
        payload["integration"]["commits"][0]["commit_url"]
        == "https://github.com/minhuw/coquic/commit/0123456789abcdef"
    )

    store.finish_task(integration.id, TaskStatus.pushed, "pushed 0123456789abcdef")
    payload = TestClient(app).get("/api/state").json()
    assert payload["integration"]["queue"] == []
    assert payload["integration"]["runs"][0]["task_id"] == integration.id
    assert payload["integration"]["runs"][0]["status"] == "pushed"


def test_web_integration_detail_returns_run_abstraction(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="Source", prompt="P")
    )
    patch = config.patches_dir / f"{source.id}.patch"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_text("diff\n", encoding="utf-8")
    source.patch_path = patch
    store.save(source)
    source = store.update_status(source.id, TaskStatus.integrating, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate Source",
            prompt="Integrate",
            metadata={
                "source_task_id": source.id,
                "source_patch_path": str(patch),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )
    store.add_event(
        integration.id,
        "integration.source",
        source.id,
        {"source_task_id": source.id, "source_patch_path": str(patch)},
    )
    store.add_event(
        source.id,
        "integration.started",
        integration.id,
        {"integration_task_id": integration.id},
    )
    commit_dir = config.transcripts_dir / integration.id / "commit-message"
    commit_dir.mkdir(parents=True)
    (commit_dir / "last-message.md").write_text(
        '{"subject":"fix: test integration","body":"Body"}',
        encoding="utf-8",
    )
    (commit_dir / "codex.jsonl").write_text(
        '{"type":"turn.completed"}\n',
        encoding="utf-8",
    )
    push_log = config.logs_dir / integration.id / "git-push.txt"
    push_log.parent.mkdir(parents=True)
    push_log.write_text("$ git push origin HEAD:main\nexit: 0\n", encoding="utf-8")
    store.add_event(integration.id, "main.pushed", "0123456789abcdef")
    app = create_app()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.get(f"/api/integrations/{integration.id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["run_id"] == integration.id
    assert payload["run"]["task_id"] == integration.id
    assert payload["run"]["source_task_id"] == source.id
    assert payload["run"]["source_title"] == "Source"
    assert payload["run"]["source_patch_path"] == str(patch)
    assert payload["run"]["transcript_path"] is None
    assert payload["source_task"]["spec"]["id"] == source.id
    assert [event["kind"] for event in payload["events"]] == [
        "task.created",
        "integration.source",
        "main.pushed",
    ]
    assert [event["kind"] for event in payload["source_events"]] == [
        "integration.started"
    ]
    assert payload["remote"]["commit"] == "0123456789abcdef"
    assert (
        payload["remote"]["commit_url"]
        == "https://github.com/minhuw/coquic/commit/0123456789abcdef"
    )
    assert payload["commit_message"]["last_message_path"] == str(
        commit_dir / "last-message.md"
    )
    assert payload["commit_message"]["last_message"].startswith(
        '{"subject":"fix: test integration"'
    )
    assert payload["push_log"]["path"] == str(push_log)
    assert "$ git push origin HEAD:main" in payload["push_log"]["text"]
    assert client.get(f"/api/integrations/{source.id}").status_code == 404


def test_tail_text_can_skip_partial_first_line(tmp_path: Path) -> None:
    from coquic_steward.web.app import tail_text

    path = tmp_path / "codex.jsonl"
    path.write_text(
        '{"type":"item.completed","item":{"id":"1"}}\n'
        '{"type":"item.completed","item":{"id":"2"}}\n',
        encoding="utf-8",
    )

    text = tail_text(path, max_bytes=55, line_aligned=True)

    assert text == '{"type":"item.completed","item":{"id":"2"}}\n'


def test_web_task_asset_serves_task_image(config: StewardConfig, monkeypatch) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.worktrees_dir / task.id
    task.worktree_path.mkdir(parents=True)
    image = task.worktree_path / "plot.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n")
    store.save(task)
    app = create_app()
    from fastapi.testclient import TestClient

    response = TestClient(app).get(
        f"/api/tasks/{task.id}/assets", params={"path": "plot.png"}
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content == b"\x89PNG\r\n\x1a\n"


def test_web_task_asset_serves_absolute_task_image(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.worktrees_dir / task.id
    task.worktree_path.mkdir(parents=True)
    image = task.worktree_path / "plot.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n")
    store.save(task)
    app = create_app()
    from fastapi.testclient import TestClient

    response = TestClient(app).get(
        f"/api/tasks/{task.id}/assets", params={"path": str(image)}
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"


def test_web_task_asset_rejects_relative_escape(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.worktrees_dir / task.id
    task.worktree_path.mkdir(parents=True)
    outside = config.worktrees_dir / "outside.png"
    outside.write_bytes(b"\x89PNG\r\n\x1a\n")
    store.save(task)
    app = create_app()
    from fastapi.testclient import TestClient

    response = TestClient(app).get(
        f"/api/tasks/{task.id}/assets", params={"path": "../outside.png"}
    )

    assert response.status_code == 403


def test_web_task_asset_rejects_non_image(config: StewardConfig, monkeypatch) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.worktrees_dir / task.id
    task.worktree_path.mkdir(parents=True)
    text = task.worktree_path / "notes.txt"
    text.write_text("not image\n", encoding="utf-8")
    store.save(task)
    app = create_app()
    from fastapi.testclient import TestClient

    response = TestClient(app).get(
        f"/api/tasks/{task.id}/assets", params={"path": "notes.txt"}
    )

    assert response.status_code == 415


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

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
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
from coquic_steward.agents.tool_changes import ToolChangeCapture, handle_hook
from coquic_steward.agents.diagnostics import diagnostics_for_paths
from coquic_steward.agents.runner import _is_transient_codex_message
from coquic_steward.core.config import (
    PathPolicyConfig,
    StewardConfig,
    StewardLimits,
    load_config,
)
from coquic_steward.core.lifecycle import InvalidTaskTransition
from coquic_steward.core.models import (
    DaemonRuntime,
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
    TaskWorkflow,
    ValidationResult,
    WorkerKind,
    WorkerResult,
    new_scheduler_wakeup_id,
    new_signal_fetch_id,
    new_task_id,
    utc_now,
)
from coquic_steward.core.subprocesses import CommandResult, run_command
from coquic_steward.execution import StewardExecutor, Worktrees
from coquic_steward.execution.executor import (
    _is_transient_push_failure,
    commit_message_schema_path,
    frozen_patch_paths,
    parse_commit_message,
    render_commit_message_prompt,
)
from coquic_steward.execution.review import (
    parse_review,
    render_review_revision_prompt,
    review_approved,
    review_schema_path,
)
from coquic_steward.execution.validation import (
    default_gates,
    render_validation_revision_prompt,
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
    status_stale_minutes,
    wait_for_scheduler_event,
)
from coquic_steward.planning import (
    CodexPlanner,
    PLANNER_SYSTEM_PROMPT,
    PlannerRun,
    PlanVerifier,
    planner_schema_path,
)
from coquic_steward.control_loop import ControlLoopArchive, ControlLoopLedger
from coquic_steward.planning.verifier import ActiveTaskSummary
from coquic_steward.signals import (
    CodacyProvider,
    GitHubActionsCiProvider,
    GitHubActionsInteropProvider,
    GitHubActionsPerfProvider,
    ProviderSignalResult,
    GitHubFeatureIssuesProvider,
    collect_signal_items,
    gather_signals,
    revalidate_signal_items,
)
from coquic_steward.signals.collector import PROVIDER_TYPES
from coquic_steward.storage import TaskStore, due_provider_names, scheduler_state
from coquic_steward.storage.schema import (
    EventRow,
    SignalItemRow,
    TaskIterationRow,
    TaskRow,
    ValidationRow,
)


def git_branch_exists(repo: Path, branch: str) -> bool:
    result = run_command(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=repo,
    )
    return result.returncode == 0


def git_branch_head(repo: Path, branch: str) -> str:
    return run_command(
        ["git", "rev-parse", branch], cwd=repo, check=True
    ).stdout.strip()


def ingest_test_signal(store: TaskStore, item: SignalItem) -> SignalItem:
    saved, _signals, _created = store.ingest_signal_collection(
        SignalFetchRun(
            id=new_signal_fetch_id(),
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
    )
    return saved[0]


def test_config_defaults_from_repo(repo: Path, coquic_home: Path) -> None:
    config = load_config(repo_root=repo)
    assert config.repo_root == repo
    assert config.steward_home == coquic_home / "steward"
    assert config.state_dir == coquic_home / "steward"
    assert config.db_path == coquic_home / "steward.sqlite"
    assert config.db_path.name == "steward.sqlite"
    assert config.legacy_json_path == config.state_dir / "steward.json"
    assert config.worktrees_dir == coquic_home / "worktrees"
    assert config.tasks_dir == coquic_home / "tasks"
    assert config.private_root == coquic_home / "private"
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
        "github-issues:features",
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
    assert config.signal_providers["github-issues:features"].poll_interval_minutes == 360
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


def test_config_reads_global_and_kind_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy]
frozen = [".github/**", "flake.nix"]

[steward.path_policy.feature]
frozen = [".clang-tidy", "scripts/run-clang-tidy.sh"]
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.path_policy.frozen == (".github/**", "flake.nix")
    assert config.path_policy.frozen_for_kind(TaskKind.feature) == (
        ".github/**",
        "flake.nix",
        ".clang-tidy",
        "scripts/run-clang-tidy.sh",
    )
    assert config.path_policy.frozen_for_kind(TaskKind.ci) == (
        ".github/**",
        "flake.nix",
    )


def test_example_config_freezes_validation_gate_runner(repo: Path) -> None:
    config = load_config(
        repo_root=repo,
        config_path=Path(__file__).resolve().parents[1] / "steward.example.toml",
    )

    assert "scripts/run-validation-with-index.sh" in config.path_policy.frozen


def test_config_rejects_absolute_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy]
frozen = ["/etc/passwd"]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="repository-relative"):
        load_config(repo_root=repo, config_path=config_path)


def test_config_rejects_blank_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy]
frozen = [""]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must not be empty"):
        load_config(repo_root=repo, config_path=config_path)


def test_config_rejects_blank_kind_frozen_paths(repo: Path) -> None:
    config_path = repo / "steward.toml"
    config_path.write_text(
        """
[steward]
github_repository = "minhuw/coquic"

[steward.path_policy.feature]
frozen = ["   "]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must not be empty"):
        load_config(repo_root=repo, config_path=config_path)


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


def test_config_reads_codex_model_and_reasoning_effort(
    repo: Path, tmp_path: Path
) -> None:
    config_path = tmp_path / "steward.toml"
    config_path.write_text(
        """
[steward]
codex_model = "gpt-5.6-terra"
codex_reasoning_effort = "medium"
""",
        encoding="utf-8",
    )

    config = load_config(repo_root=repo, config_path=config_path)

    assert config.codex_model == "gpt-5.6-terra"
    assert config.codex_reasoning_effort == "medium"


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
    make_task_legacy(store, task.id)
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
    make_task_legacy(store, task.id)
    store.start_worker(task.id, "worker started")
    make_task_stale(store, task.id)

    result = StewardDaemon(config, store).tick(plan=False, dispatch=False)

    assert result.recovered == 1
    assert store.get(task.id).status == TaskStatus.failed
    assert not worktree.exists()
    assert any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_daemon_preserves_recovered_stale_integration_commit(
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
    worktree, branch = Worktrees(config).create(integration)
    (worktree / "README.md").write_text("interrupted integration\n", encoding="utf-8")
    integration.worktree_path = worktree
    integration.branch_name = branch
    store.save(integration)
    integration = store.start_integration(integration.id, "integration started")

    # Simulate termination after Git commits but before the database event is written.
    sha = Worktrees(config).commit_all(
        worktree,
        "fix(docs): preserve interrupted integration",
        "Keep the commit reachable.",
    )
    assert sha is not None
    assert not any(
        event.kind == "integration.commit_created"
        for event in store.events(integration.id)
    )
    make_task_legacy(store, integration.id)
    store.start_integration(integration.id, "pushing to main")
    make_task_stale(store, integration.id)

    result = StewardDaemon(config, store).tick(plan=False, dispatch=False)

    saved = store.get(integration.id)
    cleaned = next(
        event for event in store.events(integration.id) if event.kind == "worktree.cleaned"
    )
    assert result.recovered == 1
    assert saved.status == TaskStatus.failed
    assert saved.summary.startswith("stale active task recovered")
    assert saved.worktree_path is not None
    assert not saved.worktree_path.exists()
    assert git_branch_head(config.repo_root, branch) == sha
    assert cleaned.data["branch_preserved"] is True


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
    make_task_legacy(store, task.id)
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


@pytest.mark.parametrize(
    "terminal_status",
    [TaskStatus.no_changes, TaskStatus.pushed, TaskStatus.succeeded],
)
def test_store_permanently_suppresses_resolved_planned_signal(
    config: StewardConfig, terminal_status: TaskStatus
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
    store.finish_task(task.id, terminal_status, str(terminal_status))
    old = utc_now() - timedelta(hours=25)
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
        )
    )

    assert not duplicate_created
    assert second.id == first.id
    assert store.pending_signal_items() == []
    assert [item.id for item in store.list_signal_items()] == [first.id]


def test_store_matches_legacy_workflow_signal_by_run_attempt(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.ci, worker=WorkerKind.ci_doctor, title="T", prompt="P")
    )
    first, created = store.add_signal_item(
        SignalItem(
            id="wi-ci-legacy",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="legacy-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100"},
        )
    )
    assert created
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.no_changes, "no changes")

    same_attempt, duplicate_created = store.add_signal_item(
        SignalItem(
            id="wi-ci-stable",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="stable-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100", "run_attempt": 1},
        )
    )
    next_attempt, next_attempt_created = store.add_signal_item(
        SignalItem(
            id="wi-ci-attempt-2",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="attempt-2-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100", "run_attempt": 2},
        )
    )

    assert not duplicate_created
    assert same_attempt.id == first.id
    assert next_attempt_created
    assert next_attempt.id == "wi-ci-attempt-2"


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


def test_store_requeues_failed_planned_signal_after_retry_window(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = store.add_signal_item(
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
        [signal.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()

    requeued = store.requeue_failed_signal_items()

    assert requeued == 1
    pending = store.pending_signal_items()
    assert [item.id for item in pending] == [signal.id]
    assert pending[0].planned_at is None
    assert pending[0].planner_run_id is None
    assert pending[0].planned_task_id is None


def test_store_skips_failed_signal_requeue_with_duplicate_pending(
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
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, first.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
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

    requeued = store.requeue_failed_signal_items()

    assert requeued == 0
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert [item.id for item in planned] == [first.id]


def test_store_skips_failed_signal_requeue_with_duplicate_planned(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    first_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T1", prompt="P")
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
        [first.id], planner_run_id="planner-1", task_id=first_task.id
    )
    store.finish_task(first_task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, first.id)
        task_row = session.get(TaskRow, first_task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
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
    second_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T2", prompt="P")
    )
    store.mark_signal_items_planned(
        [second.id], planner_run_id="planner-2", task_id=second_task.id
    )

    requeued = store.requeue_failed_signal_items()

    assert requeued == 0
    assert store.pending_signal_items() == []
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert {item.id for item in planned} == {first.id, second.id}


def test_store_requeues_failed_signal_with_stale_terminal_planned_duplicate(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    first_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T1", prompt="P")
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
        [first.id], planner_run_id="planner-1", task_id=first_task.id
    )
    store.finish_task(first_task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=49)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, first.id)
        task_row = session.get(TaskRow, first_task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
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
    second_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T2", prompt="P")
    )
    store.mark_signal_items_planned(
        [second.id], planner_run_id="planner-2", task_id=second_task.id
    )
    store.finish_task(second_task.id, TaskStatus.failed, "failed")
    retry_at = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, second.id)
        task_row = session.get(TaskRow, second_task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = retry_at.isoformat()
        signal_row.updated_at = retry_at.isoformat()
        task_row.updated_at = retry_at.isoformat()

    requeued = store.requeue_failed_signal_items()

    assert requeued == 1
    assert [item.id for item in store.pending_signal_items()] == [second.id]
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert [item.id for item in planned] == [first.id]


def test_store_does_not_requeue_recent_failed_signal(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = store.add_signal_item(
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
        [signal.id], planner_run_id="planner-1", task_id=task.id
    )
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        assert signal_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
    store.finish_task(task.id, TaskStatus.failed, "failed")

    requeued = store.requeue_failed_signal_items()

    assert requeued == 0
    assert store.pending_signal_items() == []
    planned = store.list_signal_items(status=SignalItemStatus.planned)
    assert [item.id for item in planned] == [signal.id]


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
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
        ),
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
    transition = next(
        event
        for event in store.control_loop.list_events()
        if event.kind == "signal.transition"
    )
    assert transition.payload["transition"]["toStatus"] == "planned"


def test_store_supersedes_consumed_signal_items_without_tasks(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
        ),
    )

    superseded = store.supersede_signal_items(
        ["wi-codeql-1"], planner_run_id="planner-1"
    )

    assert superseded == 1
    item = store.list_signal_items()[0]
    assert item.status == SignalItemStatus.superseded
    assert item.planner_run_id == "planner-1"
    assert store.pending_signal_items() == []
    transition = next(
        event
        for event in store.control_loop.list_events()
        if event.kind == "signal.transition"
    )
    assert transition.payload["transition"]["toStatus"] == "superseded"


def test_daemon_supersedes_stale_signals_before_planning(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    signal, _ = store.add_signal_item(
        SignalItem(
            id="wi-codeql-42",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-42",
            title="CodeQL alert 42",
            payload={"alert_number": 42},
        )
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.revalidate_signal_items",
        lambda _config, _items: ([], {signal.id: "source_not_open"}),
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda *_args: pytest.fail("planner should not run for stale signals"),
    )

    result = StewardDaemon(config, store).tick(dispatch=False)

    assert result.enqueued == 0
    saved = store.list_signal_items()[0]
    assert saved.status == SignalItemStatus.superseded
    assert saved.planner_run_id == "source-revalidation"
    event = next(
        event
        for event in store.events(DAEMON_EVENT_TASK_ID)
        if event.kind == "signals.superseded_stale"
    )
    assert event.data == {
        "count": 1,
        "reasons": {signal.id: "source_not_open"},
    }


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
    make_task_legacy(store, task.id)
    store.update_status(task.id, TaskStatus.running, "started")
    make_task_stale(store, task.id)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda _config: [],
    )
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="Open CodeQL findings",
        ),
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        lambda _config, _signals, _active, **_kwargs: PlannerRun(
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


def test_daemon_replans_expired_failed_signal_without_refetch(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="CodeQL alert",
        ),
    )
    store.mark_signal_items_planned(
        [signal.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    old = utc_now() - timedelta(hours=25)
    with Session(store.engine) as session, session.begin():
        signal_row = session.get(SignalItemRow, signal.id)
        task_row = session.get(TaskRow, task.id)
        assert signal_row is not None
        assert task_row is not None
        signal_row.planned_at = old.isoformat()
        signal_row.updated_at = old.isoformat()
        task_row.updated_at = old.isoformat()
    store.consume_wakeups([wakeup.id for wakeup in store.pending_wakeups()])

    seen_inbox: list[list[str]] = []

    def fake_run_planner(_config, signals, _active, **_kwargs):
        seen_inbox.append([item.id for item in signals.items])
        return PlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=_config.transcripts_dir / "planner" / "codex.jsonl",
            thread_id=None,
            consumed_item_ids=[],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.collect_signal_items",
        lambda *_args, **_kwargs: pytest.fail("signals should not be fetched"),
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner",
        fake_run_planner,
    )

    result = StewardDaemon(config, store).tick(plan=True, dispatch=False)

    assert result.planned == 0
    assert seen_inbox == [[signal.id]]
    assert [item.id for item in store.pending_signal_items()] == [signal.id]
    assert any(
        event.kind == "signals.requeued_failed"
        for event in store.events(DAEMON_EVENT_TASK_ID)
    )
    assert any(
        event.kind == "signal.transition"
        and event.payload["transition"]["toStatus"] == "pending"
        for event in store.control_loop.list_events()
    )


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
    make_task_legacy(store, reviewing.id)
    make_task_legacy(store, running.id)
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
    make_task_legacy(store, task.id)
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
    make_task_legacy(store, task.id)
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


def test_store_recovers_validation_phase_with_validation_timeout(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="V", prompt="V")
    )
    store.start_worker(task.id, "worker started")
    store.start_validation(task.id, "validation running: retry")
    make_task_legacy(store, task.id)
    validation_started_at = utc_now() - timedelta(minutes=40)
    with Session(store.engine) as session, session.begin():
        task_row = session.get(TaskRow, task.id)
        assert task_row is not None
        task_row.updated_at = utc_now().isoformat()
        event = (
            session.query(EventRow)
            .filter_by(task_id=task.id, kind="task.status", message="running")
            .order_by(EventRow.id.desc())
            .first()
        )
        assert event is not None
        event.created_at = validation_started_at.isoformat()

    recovered = store.recover_stale_active_tasks(
        stale_after_minutes=125,
        status_stale_after_minutes={"validation": 35},
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
        "previous_status": "running",
        "effective_status": "validation",
        "stale_after_minutes": 35,
    }


def test_status_stale_minutes_includes_validation_timeout(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "limits": StewardLimits(
                worker_timeout_minutes=120,
                review_timeout_minutes=20,
                validation_timeout_minutes=30,
            ),
        }
    )

    assert status_stale_minutes(config) == {
        "implementation_plan": 35,
        "reviewing": 25,
        "validation": 35,
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


def test_daemon_preflight_rejects_divergent_local_main(
    config: StewardConfig, tmp_path: Path
) -> None:
    remote = tmp_path / "origin.git"
    run_command(["git", "init", "--bare", str(remote)], cwd=tmp_path, check=True)
    run_command(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    run_command(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    (config.repo_root / "LOCAL.md").write_text("local only\n", encoding="utf-8")
    run_command(["git", "add", "LOCAL.md"], cwd=config.repo_root, check=True)
    run_command(
        ["git", "commit", "-m", "local change"], cwd=config.repo_root, check=True
    )
    config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
        }
    )

    with pytest.raises(StewardPreflightError) as exc_info:
        StewardDaemon(config, TaskStore(config.db_path))

    message = str(exc_info.value)
    assert "local main does not match remote main" in message
    assert "ahead/behind: 1\t0" in message
    assert "reconcile and push local main" in message


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
    inbox_item = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codeql-1",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-1",
            title="Open CodeQL findings",
            payload={"id": "wi-codeql-1", "provider": "code-scanning", "kind": "codeql-alert"},
        ),
    )

    def fake_run_planner(_config, _signals, _active, **_kwargs):
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
            thread_id=None,
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
    assert events[1].data["thread_id"] is None
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

    def fake_plan(_config, _signals, _active, **_kwargs):
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
    ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="wi-codacy-1",
            title="Open Codacy findings",
        ),
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


def test_daemon_dispatch_exception_preserves_terminal_task_status(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_run(task_id: str) -> bool:
        store.finish_task(task_id, TaskStatus.blocked, "blocked before crash")
        raise RuntimeError("after terminal update")

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "run_task", fake_run)

    result = daemon.tick(plan=False, dispatch=True)
    saved = store.get(task.id)

    assert result.skipped == 1
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "blocked before crash"
    assert any(event.kind == "dispatch.failed" for event in store.events(task.id))


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


def test_daemon_forever_dispatches_up_to_source_capacity_per_cycle(
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

    assert calls == [
        {
            "fetch_providers": [],
            "max_dispatch": config.limits.max_active_tasks,
            "reason": "wakeup",
        }
    ]


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
        ingest_test_signal(
            store,
            SignalItem(
                id=f"wi-codacy-{index}",
                provider="codacy",
                kind="codacy.issue",
                fingerprint=f"wi-codacy-{index}",
                title=f"Codacy finding {index}",
                payload={"id": f"wi-codacy-{index}", "kind": "codacy-issue"},
            ),
        )
    seen_batches: list[list[str]] = []

    def fake_plan(_config, signals, _active, **_kwargs):
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


def test_plan_verifier_accepts_feature_issue_proposal() -> None:
    item = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42: Add QUIC DATAGRAM send API",
        summary="GitHub issue #42 requests feature work",
        links=[
            {
                "label": "Open GitHub issue",
                "url": "https://github.com/minhuw/coquic/issues/42",
            }
        ],
        payload={
            "issue_number": 42,
            "issue_url": "https://github.com/minhuw/coquic/issues/42",
            "issue_title": "Add QUIC DATAGRAM send API",
            "labels": ["steward:enhancement"],
            "worker_context": {
                "recommended_task_kind": "feature",
                "recommended_worker": "feature-implementer",
            },
        },
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[item])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42 Add QUIC DATAGRAM send API",
              "prompt": "Implement GitHub issue #42 only: https://github.com/minhuw/coquic/issues/42. Add focused validation and do not mutate the issue remotely.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.consumed_item_ids == ["wi-feature-42"]
    assert len(verified.planned) == 1
    spec, dedupe_key = verified.planned[0]
    assert dedupe_key == "github-issue:42"
    assert spec.kind == TaskKind.feature
    assert spec.worker == WorkerKind.feature_implementer
    selected = spec.metadata["source_context"]["selected_signal_items"][0]
    assert selected["payload"]["issue_number"] == 42
    assert selected["payload"]["worker_context"]["recommended_worker"] == "feature-implementer"


def test_plan_verifier_rejects_mutating_worker_for_feature_issue() -> None:
    item = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[item])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "issue-implementer",
              "title": "Implement #42",
              "prompt": "Implement GitHub issue #42 locally.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []


def test_plan_verifier_rejects_multiple_feature_issues_in_one_task() -> None:
    first = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    second = SignalItem(
        id="wi-feature-43",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-43",
        title="Implement #43",
        summary="GitHub issue #43 requests feature work",
        payload={"issue_number": 43},
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[first, second])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42", "wi-feature-43"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42-43",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42 and #43",
              "prompt": "Implement both GitHub issues locally.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42", "wi-feature-43"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42", "wi-feature-43"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []


def test_plan_verifier_rejects_mixed_feature_issue_source_selection() -> None:
    feature = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    codacy = SignalItem(
        id="wi-codacy-1",
        provider="codacy",
        kind="codacy.issue",
        fingerprint="wi-codacy-1",
        title="Codacy issue",
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[feature, codacy])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-feature-42", "wi-codacy-1"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42 and fix Codacy",
              "prompt": "Implement GitHub issue #42 and fix the Codacy issue.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-feature-42", "wi-codacy-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42", "wi-codacy-1"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []


def test_plan_verifier_rejects_mismatched_feature_issue_evidence() -> None:
    feature = SignalItem(
        id="wi-feature-42",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-42",
        title="Implement #42",
        summary="GitHub issue #42 requests feature work",
        payload={"issue_number": 42},
    )
    codacy = SignalItem(
        id="wi-codacy-1",
        provider="codacy",
        kind="codacy.issue",
        fingerprint="wi-codacy-1",
        title="Codacy issue",
    )
    signals = ProjectSignals(repository="minhuw/coquic", items=[feature, codacy])

    verified = PlanVerifier().verify_plan(
        """
        {
          "consumed_item_ids": ["wi-codacy-1"],
          "tasks": [
            {
              "dedupe_key": "github-issue:42",
              "kind": "feature",
              "worker": "feature-implementer",
              "title": "Implement #42",
              "prompt": "Implement GitHub issue #42.",
              "priority": "medium",
              "risk": "medium",
              "evidence": ["wi-codacy-1"],
              "metadata": {
                "selected_signal_item_ids": ["wi-feature-42"]
              }
            }
          ]
        }
        """,
        signals,
        [],
    )

    assert verified.planned == []
    assert verified.consumed_item_ids == []


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
    assert not (config.state_dir / "planner-thread.txt").exists()

    planned = CodexPlanner(config).plan(
        ProjectSignals(repository="minhuw/coquic"),
        [],
    )

    assert planned == []
    args = (tmp_path / "args.txt").read_text(encoding="utf-8").splitlines()
    assert "resume" not in args
    assert "planner-thread-1" not in args
    assert args.count("--output-schema") == 2


def test_codex_runner_places_resume_options_before_session(
    config: StewardConfig, tmp_path: Path
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_model": "gpt-5.6-terra",
            "codex_reasoning_effort": "medium",
        }
    )
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
    assert args[args.index("--model") + 1] == "gpt-5.6-terra"
    assert 'model_reasoning_effort="medium"' in args
    assert args.index("--config") < args.index("planner-thread-1")
    assert "--cd" not in args
    assert "--sandbox" not in args


def test_executor_reconciles_late_write_after_authoritative_patch(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, branch = Worktrees(config).create(task)
    task.worktree_path = worktree
    task.branch_name = branch
    store.save(task)
    transcript_path = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=None,
        worker_transcript_path=transcript_path,
        worker_last_message_path=transcript_path.with_name("last-message.md"),
    )
    capture = ToolChangeCapture.start(worktree, transcript_path.parent / "tool-changes")
    envelope = {
        "hook_event_name": "PreToolUse",
        "session_id": "session_1",
        "turn_id": "turn_1",
        "cwd": str(worktree),
        "tool_name": "Bash",
        "tool_use_id": "tool_1",
        "tool_input": {"command": "printf changed > README.md"},
    }
    handle_hook(json.dumps(envelope), context_path=capture.context_path)
    (worktree / "README.md").write_text("changed\n", encoding="utf-8")
    handle_hook(
        json.dumps(
            {
                **envelope,
                "hook_event_name": "PostToolUse",
                "tool_response": {"success": True},
            }
        ),
        context_path=capture.context_path,
    )
    assert capture.finalize().state == "complete"

    executor = StewardExecutor(config, store)
    original_save = executor.worktrees.save_patch

    def save_then_write(path: Path, patch_path: Path) -> None:
        original_save(path, patch_path)
        (path / "late.txt").write_text("late\n", encoding="utf-8")

    monkeypatch.setattr(executor.worktrees, "save_patch", save_then_write)
    monkeypatch.setattr(executor, "_run_gates_for_iteration", lambda *_args: [])

    assert executor._prepare_patch(
        task.id,
        "initial",
        iteration=0,
        no_changes_status=TaskStatus.no_changes,
    ).value == "ready"
    summary = json.loads(
        (transcript_path.parent / "tool-changes" / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["state"] == "partial"
    assert "external_mutation" in summary["reasons"]


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


def test_planner_schema_file_matches_expected_shape(config: StewardConfig) -> None:
    path = planner_schema_path(config)
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == ["consumed_item_ids", "tasks"]
    assert schema["properties"]["consumed_item_ids"]["type"] == "array"
    item = schema["properties"]["tasks"]["items"]
    assert "code-quality" in item["properties"]["kind"]["enum"]
    assert "feature" in item["properties"]["kind"]["enum"]
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


def make_task_legacy(store: TaskStore, task_id: str) -> None:
    """Remove the 2.0 ledger so a fixture exercises legacy stale recovery."""

    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "DELETE FROM task_pipelines WHERE task_id = ?",
            (task_id,),
        )
        connection.exec_driver_sql(
            "DELETE FROM task_executions WHERE task_id = ?",
            (task_id,),
        )


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
    assert "github-issues:features" in PROVIDER_TYPES


def test_collect_signal_items_fetches_github_actions_alias_by_name(
    config: StewardConfig, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        captured["args"] = args
        captured["cwd"] = cwd
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 789,
                        "workflowName": "Per-Commit CI",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 2,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    collection = collect_signal_items(
        config, provider_names=["github-actions:ci"]
    )[0]

    args = captured["args"]
    assert isinstance(args, list)
    assert args[args.index("--workflow") + 1] == "ci.yml"
    assert "--status" not in args
    assert args[args.index("--limit") + 1] == "1"
    assert captured["cwd"] == config.repo_root
    assert collection.provider == "github-actions:ci"
    assert collection.fetch.provider == "github-actions:ci"
    assert collection.fetch.item_count == 1
    assert collection.items[0].provider == "github-actions:ci"
    assert collection.items[0].kind == "github-actions.ci-failure"
    assert collection.items[0].payload["run_attempt"] == 2


@pytest.mark.parametrize(
    ("status", "conclusion"),
    [("completed", "success"), ("in_progress", "")],
)
def test_github_actions_signal_ignores_latest_non_failure(
    config: StewardConfig, monkeypatch, status: str, conclusion: str
) -> None:
    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 790,
                        "workflowName": "Per-Commit CI",
                        "status": status,
                        "conclusion": conclusion,
                        "attempt": 1,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    signals = gather_signals(config, providers=[GitHubActionsCiProvider()])

    assert signals.items == []


def test_revalidate_signal_items_filters_stale_sources(
    config: StewardConfig, monkeypatch
) -> None:
    workflow = SignalItem(
        id="wi-ci-100",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="wi-ci-100",
        title="CI run 100 failed",
        payload={"run_id": "100", "run_attempt": 1},
    )
    current_workflow = workflow.model_copy(
        update={
            "id": "wi-ci-101",
            "fingerprint": "wi-ci-101",
            "title": "CI run 101 failed",
            "payload": {"run_id": "101", "run_attempt": 1},
        }
    )
    codeql = SignalItem(
        id="wi-codeql-5954",
        provider="code-scanning",
        kind="code-scanning.alert",
        fingerprint="wi-codeql-5954",
        title="CodeQL alert 5954",
        links=[
            {
                "label": "Open alert",
                "url": "https://github.com/minhuw/coquic/security/code-scanning/5954",
            }
        ],
    )
    current_codeql = codeql.model_copy(
        update={
            "id": "wi-codeql-5955",
            "fingerprint": "wi-codeql-5955",
            "title": "CodeQL alert 5955",
            "links": [
                {
                    "label": "Open alert",
                    "url": "https://github.com/minhuw/coquic/security/code-scanning/5955",
                }
            ],
        }
    )
    feature = SignalItem(
        id="wi-feature-7",
        provider="github-issues:features",
        kind="github-issues.feature-request",
        fingerprint="wi-feature-7",
        title="Issue #7",
        payload={"issue_number": 7},
    )
    current_feature = feature.model_copy(
        update={
            "id": "wi-feature-8",
            "fingerprint": "wi-feature-8",
            "title": "Issue #8",
            "payload": {"issue_number": 8},
        }
    )
    codacy = SignalItem(
        id="wi-codacy-1",
        provider="codacy",
        kind="codacy.issue",
        fingerprint="wi-codacy-1",
        title="Codacy issue",
    )

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        if args[:3] == ["gh", "run", "list"]:
            payload = [
                {
                    "databaseId": 101,
                    "workflowName": "Per-Commit CI",
                    "status": "completed",
                    "conclusion": "failure",
                    "attempt": 1,
                }
            ]
        elif args[:3] == ["gh", "api", "-X"]:
            payload = {
                "state": "open" if args[-1].endswith("/5955") else "fixed"
            }
        elif args[:3] == ["gh", "issue", "view"]:
            payload = (
                {"state": "OPEN", "labels": [{"name": "steward:feature"}]}
                if args[3] == "8"
                else {"state": "CLOSED", "labels": []}
            )
        else:  # pragma: no cover - protects the command contract.
            raise AssertionError(args)
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    actionable, stale = revalidate_signal_items(
        config,
        [
            workflow,
            current_workflow,
            codeql,
            current_codeql,
            feature,
            current_feature,
            codacy,
        ],
    )

    assert actionable == [current_workflow, current_codeql, current_feature, codacy]
    assert stale == {
        workflow.id: "superseded_by_newer_run",
        codeql.id: "source_not_open",
        feature.id: "source_closed",
    }


def test_revalidate_signal_items_treats_legacy_workflow_as_attempt_one(
    config: StewardConfig, monkeypatch
) -> None:
    item = SignalItem(
        id="wi-ci-100",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="wi-ci-100",
        title="CI run 100 failed",
        payload={"run_id": "100"},
    )

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "databaseId": 100,
                        "workflowName": "Per-Commit CI",
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 2,
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    actionable, stale = revalidate_signal_items(config, [item])

    assert actionable == []
    assert stale == {item.id: "superseded_by_newer_run"}


def test_revalidate_signal_items_fails_open(
    config: StewardConfig, monkeypatch
) -> None:
    item = SignalItem(
        id="wi-ci-100",
        provider="github-actions:ci",
        kind="github-actions.ci-failure",
        fingerprint="wi-ci-100",
        title="CI run 100 failed",
        payload={"run_id": "100", "run_attempt": 1},
    )

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=1,
            stdout="",
            stderr="GitHub unavailable",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command", fake_run_command
    )

    actionable, stale = revalidate_signal_items(config, [item])

    assert actionable == [item]
    assert stale == {}


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
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
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
    assert "--status" not in args
    assert captured["cwd"] == config.repo_root
    assert len(signals.items) == 1
    item = signals.items[0]
    assert item.provider == "github-actions:interop"
    assert item.id.startswith("wi-github-actions-interop-interop-failure-")
    assert item.kind == "github-actions.interop-failure"
    assert item.payload["run_id"] == "123"
    assert item.payload["run_attempt"] == 1
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
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
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
                        "status": "completed",
                        "conclusion": "failure",
                        "attempt": 1,
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


def test_github_feature_issue_signal_fetches_open_feature_issues(
    config: StewardConfig, monkeypatch
) -> None:
    calls: list[list[str]] = []

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        calls.append(args)
        label = args[args.index("--label") + 1]
        payload = []
        if label == "steward:enhancement":
            payload = [
                {
                    "number": 42,
                    "title": "Add QUIC DATAGRAM send API",
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "body": "Expose an application-facing datagram sender.",
                    "labels": [{"name": "steward:enhancement"}, {"name": "api"}],
                    "author": {"login": "alice"},
                    "createdAt": "2026-06-01T00:00:00Z",
                    "updatedAt": "2026-06-02T00:00:00Z",
                    "state": "open",
                }
            ]
        if label == "steward:feature":
            payload = [
                {
                    "number": 42,
                    "title": "Add QUIC DATAGRAM send API",
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "body": "Duplicate through steward feature label.",
                    "labels": [{"name": "steward:feature"}],
                    "author": {"login": "alice"},
                    "createdAt": "2026-06-01T00:00:00Z",
                    "updatedAt": "2026-06-03T00:00:00Z",
                    "state": "open",
                }
            ]
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    signals = gather_signals(config, providers=[GitHubFeatureIssuesProvider()])

    assert [call[:3] for call in calls] == [
        ["gh", "search", "issues"],
        ["gh", "search", "issues"],
    ]
    for call in calls:
        assert call[call.index("--repo") + 1] == "minhuw/coquic"
        assert call[call.index("--state") + 1] == "open"
        assert call[call.index("--limit") + 1] == "13"
        assert call[call.index("--json") + 1] == (
            "number,title,url,body,labels,author,createdAt,updatedAt,state"
        )
    assert [call[call.index("--label") + 1] for call in calls] == [
        "steward:enhancement",
        "steward:feature",
    ]
    assert signals.enabled_signals == ["github-issues:features"]
    assert signals.summary == "GitHub issues sampled 1 open feature request(s): #42"
    assert len(signals.items) == 1
    item = signals.items[0]
    assert item.id.startswith("wi-github-issues-features-feature-request-")
    assert item.provider == "github-issues:features"
    assert item.kind == "github-issues.feature-request"
    assert item.title == "Implement #42: Add QUIC DATAGRAM send API"
    assert item.summary == (
        "GitHub issue #42 requests feature work: Add QUIC DATAGRAM send API "
        "labels=steward:enhancement, api"
    )
    assert item.links == [
        {
            "label": "Open GitHub issue",
            "url": "https://github.com/minhuw/coquic/issues/42",
        }
    ]
    assert item.payload["issue_number"] == 42
    assert item.payload["issue_url"] == "https://github.com/minhuw/coquic/issues/42"
    assert item.payload["labels"] == ["steward:enhancement", "api"]
    assert item.payload["author"] == "alice"
    assert item.payload["body_excerpt"] == "Expose an application-facing datagram sender."
    assert item.payload["worker_context"]["recommended_task_kind"] == "feature"
    assert item.payload["worker_context"]["recommended_worker"] == "feature-implementer"
    assert "selected issue" in " ".join(
        item.payload["worker_context"]["implementation_steps"]
    )


def test_github_feature_issue_signal_reports_truncated_samples(
    config: StewardConfig, monkeypatch
) -> None:
    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        label = args[args.index("--label") + 1]
        payload = []
        if label == "steward:enhancement":
            payload = [
                {
                    "number": number,
                    "title": f"Feature {number}",
                    "url": f"https://github.com/minhuw/coquic/issues/{number}",
                    "labels": [{"name": "steward:enhancement"}],
                }
                for number in range(1, 4)
            ]
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )

    result = GitHubFeatureIssuesProvider().collect(config, max_items=2)

    assert len(result.items) == 2
    assert result.has_more is True


def test_github_feature_issue_signal_fingerprint_survives_title_edits(
    config: StewardConfig, monkeypatch
) -> None:
    titles = ["Initial title", "Edited title"]

    def fake_run_command(args, cwd, *, timeout=None, **_kwargs):
        label = args[args.index("--label") + 1]
        payload = []
        if label == "steward:enhancement":
            payload = [
                {
                    "number": 42,
                    "title": titles.pop(0),
                    "url": "https://github.com/minhuw/coquic/issues/42",
                    "labels": [{"name": "steward:enhancement"}],
                }
            ]
        return CommandResult(
            args=args,
            cwd=cwd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        "coquic_steward.signals.providers.run_command",
        fake_run_command,
    )
    provider = GitHubFeatureIssuesProvider()

    first = provider.collect(config, max_items=1).items[0]
    second = provider.collect(config, max_items=1).items[0]

    assert first.title == "Implement #42: Initial title"
    assert second.title == "Implement #42: Edited title"
    assert first.id == second.id
    assert first.fingerprint == second.fingerprint


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
                b'"filePath":"steward/src/coquic_steward/public_mirror.py",'
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
        "path": "steward/src/coquic_steward/public_mirror.py",
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


def test_worker_prompt_highlights_feature_issue_signal_guidance(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={
                    TaskKind.feature.value: ("flake.nix", ".github/**")
                }
            ),
        }
    )
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="Implement #42 Add QUIC DATAGRAM send API",
            prompt="Implement the selected GitHub issue.",
            metadata={
                "source_context": {
                    "selected_signal_item_ids": ["wi-feature-42"],
                    "selected_signal_items": [
                        {
                            "id": "wi-feature-42",
                            "provider": "github-issues:features",
                            "kind": "github-issues.feature-request",
                            "payload": {
                                "issue_number": 42,
                                "issue_url": "https://github.com/minhuw/coquic/issues/42",
                                "issue_title": "Add QUIC DATAGRAM send API",
                                "body_excerpt": "Expose an application-facing datagram sender.",
                                "worker_context": {
                                    "recommended_task_kind": "feature",
                                    "recommended_worker": "feature-implementer",
                                    "issue_purpose": "Implement a scoped feature request.",
                                    "implementation_steps": [
                                        "Open or fetch only the selected issue to confirm it is still open.",
                                        "Steward comments on and closes the selected issue only after the reviewed patch is pushed to main.",
                                    ],
                                    "local_validation": [
                                        "nix develop -c zig build test"
                                    ],
                                    "scope_limits": [
                                        "Do not close, label, comment on, or otherwise mutate GitHub issues from the worker."
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
    assert "recommended_task_kind: feature" in prompt
    assert "recommended_worker: feature-implementer" in prompt
    assert "issue_purpose: Implement a scoped feature request." in prompt
    assert "implementation_steps:" in prompt
    assert "Open or fetch only the selected issue" in prompt
    assert "Steward comments on and closes the selected issue" in prompt
    assert "Authoritative source context:" in prompt
    assert "https://github.com/minhuw/coquic/issues/42" in prompt
    assert "Do not fetch a broad or unknown issue list" in prompt
    assert "gh-issue-implementation" not in prompt
    assert "Scope control:" in prompt
    assert "Make the smallest coherent patch" in prompt
    assert "Follow-up task proposals:" in prompt
    assert "Kind: <feature|ci|code-quality|rfc-audit|custom>" in prompt
    assert "code_quality" not in prompt
    assert "rfc_audit" not in prompt
    assert "Do not create GitHub issues, Steward tasks, commits, pushes" in prompt
    assert "Frozen path policy:" in prompt
    assert "Steward will block patches that change them" in prompt
    assert "- flake.nix" in prompt
    assert "- .github/**" in prompt


def test_worker_prompt_suppresses_mutating_issue_skill_for_feature_signal(
    config: StewardConfig,
) -> None:
    task = TaskStore(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.issue_implementer,
            title="Implement #42",
            prompt="Implement the selected GitHub issue.",
            metadata={
                "source_context": {
                    "selected_signal_items": [
                        {
                            "id": "wi-feature-42",
                            "provider": "github-issues:features",
                            "kind": "github-issues.feature-request",
                            "payload": {"issue_number": 42},
                        }
                    ],
                }
            },
        )
    )[0]
    task.worktree_path = config.repo_root

    prompt = render_worker_prompt(task, config)

    assert "Worker: Issue Implementer" in prompt
    assert "gh-issue-implementation" not in prompt
    assert "change GitHub issues" in prompt


def test_review_revision_prompt_keeps_repairs_scoped(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="Implement strict 0-RTT policy",
            prompt="Implement the selected feature.",
        )
    )[0]
    review = {
        "verdict": "block",
        "summary": "Backend work is too broad.",
        "findings": [
            {
                "severity": "high",
                "title": "Requires new backend ticket storage",
                "file": "src/quic/crypto/tls_adapter_boringssl.cpp",
                "line": 42,
                "detail": "The fix requires a backend feature.",
                "recommendation": "Split the backend prerequisite.",
            }
        ],
        "validation_gaps": [],
        "remaining_risk": "",
    }

    prompt = render_review_revision_prompt(task, review, config)

    assert "Revision scope control:" in prompt
    assert "Fix only findings that can be addressed within the original task boundary" in prompt
    assert "report a follow-up task proposal" in prompt
    assert "Follow-up task proposals:" in prompt
    assert "Kind: <feature|ci|code-quality|rfc-audit|custom>" in prompt
    assert "code_quality" not in prompt
    assert "rfc_audit" not in prompt
    assert "Do not add unrelated tooling changes" in prompt
    assert "Frozen path policy:" in prompt
    assert "- flake.nix" in prompt


def test_validation_revision_prompt_keeps_tooling_repairs_out_of_feature_patch(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: (".clang-tidy",)}
            ),
        }
    )
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="Implement strict 0-RTT policy",
            prompt="Implement the selected feature.",
        )
    )[0]
    validation = ValidationResult(
        command=["nix", "develop", "-c", "pre-commit", "run", "--all-files"],
        cwd=config.repo_root,
        passed=False,
        exit_code=1,
        output_path=config.logs_dir / "pre-commit.txt",
        summary="clang-tidy failed in repo-wide tooling",
    )

    prompt = render_validation_revision_prompt(task, [validation], config)

    assert "Validation repair scope control:" in prompt
    assert "Do not change repo-wide tooling" in prompt
    assert "report a follow-up task proposal" in prompt
    assert "Follow-up task proposals:" in prompt
    assert "Kind: <feature|ci|code-quality|rfc-audit|custom>" in prompt
    assert "code_quality" not in prompt
    assert "rfc_audit" not in prompt
    assert "nix develop -c pre-commit run --all-files" in prompt
    assert "Frozen path policy:" in prompt
    assert "- .clang-tidy" in prompt


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


def test_worktree_create_uses_fresh_remote_main_when_local_main_diverges(
    config: StewardConfig, tmp_path: Path
) -> None:
    remote = tmp_path / "origin.git"
    upstream = tmp_path / "upstream"
    run_command(["git", "init", "--bare", str(remote)], cwd=tmp_path, check=True)
    run_command(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    run_command(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
    run_command(
        ["git", "clone", "--branch", "main", str(remote), str(upstream)],
        cwd=tmp_path,
        check=True,
    )
    run_command(
        ["git", "config", "user.email", "steward@example.test"],
        cwd=upstream,
        check=True,
    )
    run_command(
        ["git", "config", "user.name", "Steward Test"],
        cwd=upstream,
        check=True,
    )
    (upstream / "README.md").write_text("remote\n", encoding="utf-8")
    run_command(["git", "add", "README.md"], cwd=upstream, check=True)
    run_command(["git", "commit", "-m", "remote change"], cwd=upstream, check=True)
    run_command(["git", "push", "origin", "main"], cwd=upstream, check=True)

    (config.repo_root / "LOCAL.md").write_text("local only\n", encoding="utf-8")
    run_command(["git", "add", "LOCAL.md"], cwd=config.repo_root, check=True)
    run_command(
        ["git", "commit", "-m", "local change"], cwd=config.repo_root, check=True
    )
    push_config = config.__class__(
        **{
            **config.__dict__,
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": False,
        }
    )
    store = TaskStore(push_config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    path, _ = Worktrees(push_config).create(task)

    worktree_head = run_command(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True
    ).stdout.strip()
    remote_head = run_command(
        ["git", "rev-parse", "origin/main"], cwd=config.repo_root, check=True
    ).stdout.strip()
    assert worktree_head == remote_head
    assert (path / "README.md").read_text(encoding="utf-8") == "remote\n"
    assert not (path / "LOCAL.md").exists()


def test_commit_all_skips_hooks_only_for_the_validated_tree(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    (path / "README.md").write_text("validated\n", encoding="utf-8")
    validated_tree = worktrees.stage_tree(path)
    hook_marker = tmp_path / "hook-ran"
    hook = config.repo_root / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        f"#!/bin/sh\ntouch '{hook_marker}'\nexit 1\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)

    sha = worktrees.commit_all(
        path,
        "test: commit validated tree",
        expected_tree=validated_tree,
    )

    assert sha is not None
    assert not hook_marker.exists()
    committed_tree = run_command(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=path, check=True
    ).stdout.strip()
    assert committed_tree == validated_tree


def test_commit_all_rejects_changes_after_validation(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    (path / "README.md").write_text("validated\n", encoding="utf-8")
    validated_tree = worktrees.stage_tree(path)
    head_before = run_command(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True
    ).stdout.strip()
    (path / "README.md").write_text("changed later\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="staged tree changed after validation"):
        worktrees.commit_all(
            path,
            "test: reject changed tree",
            expected_tree=validated_tree,
        )
    (path / "README.md").write_text("hello\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="staged tree changed after validation"):
        worktrees.commit_all(
            path,
            "test: reject reverted tree",
            expected_tree=validated_tree,
        )

    assert (
        run_command(["git", "rev-parse", "HEAD"], cwd=path, check=True).stdout.strip()
        == head_before
    )


def test_worktree_patch_includes_staged_and_untracked_changes(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom, worker=WorkerKind.custom, title="Source", prompt="P"
        )
    )
    target, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom, worker=WorkerKind.custom, title="Target", prompt="P"
        )
    )
    worktrees = Worktrees(config)
    source_path, _ = worktrees.create(source)
    target_path, _ = worktrees.create(target)

    (source_path / "README.md").write_text("staged\n", encoding="utf-8")
    run_command(["git", "add", "README.md"], cwd=source_path, check=True)
    untracked = source_path / "notes" / "new file.txt"
    untracked.parent.mkdir()
    untracked.write_text("untracked\n", encoding="utf-8")

    patch = worktrees.diff(source_path)
    worktrees.apply_patch(target_path, patch)

    assert (target_path / "README.md").read_text(encoding="utf-8") == "staged\n"
    assert (target_path / "notes" / "new file.txt").read_text(
        encoding="utf-8"
    ) == "untracked\n"
    assert "new file mode 100644" in patch


def test_worktree_reports_frozen_file_and_directory_changes(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={
                    TaskKind.feature.value: ("flake.nix", ".github/**")
                }
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    (path / "flake.nix").write_text("{}\n", encoding="utf-8")
    workflow = path / ".github" / "workflows" / "test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: test\n", encoding="utf-8")
    (path / "src").mkdir()
    (path / "src" / "main.cpp").write_text("int main() {}\n", encoding="utf-8")

    assert worktrees.frozen_paths(path, task) == [
        ".github/workflows/test.yml",
        "flake.nix",
    ]


def test_frozen_patch_paths_match_renamed_files(config: StewardConfig) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
        }
    )
    task = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    patch = """\
diff --git a/flake.nix b/config/flake.nix
similarity index 100%
rename from flake.nix
rename to config/flake.nix
"""

    assert frozen_patch_paths(config, task, patch) == ["flake.nix"]


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


def test_codex_runner_retries_transient_failure_and_resumes(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    count = tmp_path / "count.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'count=$(cat "{count}" 2>/dev/null || printf 0)\n'
        "count=$((count + 1))\n"
        f'printf "%s" "$count" > "{count}"\n'
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$count" -eq 1 ]; then\n'
        "  printf 'stream disconnected before completion\\n' > \"$last\"\n"
        "  printf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"thread-transient\"}'\n"
        "  exit 1\n"
        "fi\n"
        "printf 'done\\n' > \"$last\"\n"
        "printf '%s\\n' '{\"message\":\"done\"}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    delays: list[float] = []
    monkeypatch.setattr(
        "coquic_steward.agents.runner.time.sleep", lambda delay: delays.append(delay)
    )

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert result.completed
    assert result.thread_id == "thread-transient"
    assert result.diagnostics["retry_count"] == 1
    retry = result.diagnostics["retries"][0]
    assert retry["attempt"] == 1
    assert retry["next_attempt"] == 2
    assert Path(retry["transcript_path"]).exists()
    assert Path(retry["last_message_path"]).read_text(encoding="utf-8") == (
        "stream disconnected before completion\n"
    )
    archived_context = Path(retry["tool_changes_path"]) / "context.json"
    assert ToolChangeCapture.from_context(archived_context).summary.state == "unavailable"
    assert delays == [5.0]
    assert "exec resume" in calls.read_text(encoding="utf-8").splitlines()[1]
    assert "thread-transient" in calls.read_text(encoding="utf-8").splitlines()[1]
    StewardExecutor(config, store)._record_codex_retries(task.id, result)
    retry_event = next(
        event for event in store.events(task.id) if event.kind == "codex.retry"
    )
    assert retry_event.data["next_attempt"] == 2
    assert retry_event.data["stage"] == "code"


@pytest.mark.parametrize(
    "message",
    [
        "Selected model is at capacity. Please try a different model.",
        "unexpected status 503 Service Unavailable",
        "HTTP status 502",
        "Could not resolve host: cch.example.test",
    ],
)
def test_codex_transient_failure_classification(message: str) -> None:
    assert _is_transient_codex_message(message)


def test_codex_does_not_retry_deterministic_failure() -> None:
    assert not _is_transient_codex_message("invalid output schema")
    assert not _is_transient_codex_message("maximum output tokens exceeded")


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
    assert saved.branch_name is not None
    assert not saved.worktree_path.exists()
    assert not git_branch_exists(config.repo_root, saved.branch_name)
    assert any(event.kind == "worktree.cleaned" for event in store.events(task.id))


def test_executor_blocks_worker_patch_that_changes_frozen_path(
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
        "printf '{}\\n' > flake.nix\n"
        "printf 'changed frozen path\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )

    def fail_if_validated(*_args, **_kwargs):
        pytest.fail("validation should not run after a frozen path change")

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", fail_if_validated
    )

    assert not StewardExecutor(config, store).run_task(task.id)

    saved = store.get(task.id)
    events = store.events(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert any(event.kind == "path_policy.blocked" for event in events)
    assert saved.worktree_path is not None
    assert not saved.worktree_path.exists()


def test_executor_blocks_frozen_path_written_by_validation(
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
        "printf 'source change\\n' > README.md\n"
        "printf 'changed source\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )

    def fake_gates(_config, task_id, cwd, *, label=None):
        output = _config.logs_dir / task_id / (label or "validation") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert not StewardExecutor(config, store).run_task(task.id)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert saved.patch_path is None
    assert any(event.kind == "path_policy.blocked" for event in store.events(task.id))


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
    assert saved.branch_name is not None
    assert not saved.worktree_path.exists()
    assert not git_branch_exists(config.repo_root, saved.branch_name)
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


def test_executor_records_validation_results_incrementally(
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

    def fake_gates(
        _config,
        task_id,
        cwd,
        *,
        label=None,
        on_gate_start=None,
        on_gate_result=None,
    ):
        assert label == "iteration-0"
        assert on_gate_start is not None
        assert on_gate_result is not None
        results = []
        for position, command in enumerate((["gate-0"], ["gate-1"])):
            filename = f"gate-{position}.txt"
            on_gate_start(position, filename, command)
            output = _config.logs_dir / task_id / label / filename
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(f"gate {position}\n", encoding="utf-8")
            validation = ValidationResult(
                command=command,
                cwd=cwd,
                passed=True,
                exit_code=0,
                output_path=output,
                summary=f"gate {position}",
            )
            results.append(validation)
            on_gate_result(position, validation)
            observed[f"after_gate_{position}"] = [
                item.command for item in store.get(task_id).validations
            ]
        return results

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)

    assert observed == {
        "after_gate_0": [["gate-0"]],
        "after_gate_1": [["gate-0"], ["gate-1"]],
    }
    with Session(store.engine) as session:
        rows = (
            session.query(ValidationRow)
            .filter_by(task_id=task.id)
            .order_by(ValidationRow.position)
            .all()
        )
    assert [json.loads(row.command_json) for row in rows] == [
        ["gate-0"],
        ["gate-1"],
    ]
    assert [row.iteration for row in rows] == [0, 0]
    assert [row.position for row in rows] == [0, 1]
    assert [row.passed for row in rows] == [True, True]
    events = store.events(task.id)
    assert [event.kind for event in events].count("validation.command_started") == 2
    assert [event.kind for event in events].count("validation.command_finished") == 2


def test_default_gates_use_clean_pinned_worktree_nix_shell() -> None:
    worktree = Path("/task/worktree")
    prefix = [
        "nix",
        "develop",
        "--ignore-env",
        "--keep-env-var",
        "HOME",
        "git+file:///task/worktree#lint",
        "-c",
        "bash",
        "/task/worktree/scripts/run-validation-with-index.sh",
    ]
    commands = [command for _, command in default_gates(worktree)]

    assert all(command[: len(prefix)] == prefix for command in commands)
    assert commands[0][len(prefix) :] == [
        "git",
        "diff",
        "--cached",
        "--check",
        "HEAD",
        "--",
    ]
    assert commands[1][len(prefix) :] == [
        "nix",
        "flake",
        "check",
        "--no-build",
        "--no-update-lock-file",
        ".",
    ]
    assert commands[2][len(prefix) :] == ["zig", "build", "test"]
    assert commands[3][len(prefix) :] == [
        "env",
        "COQUIC_CLANG_TIDY_IN_NIX=1",
        "pre-commit",
        "run",
        "--all-files",
    ]


def test_validation_index_includes_untracked_files_without_mutating_worker_index(
    repo: Path,
) -> None:
    runner = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "run-validation-with-index.sh"
    )
    (repo / "README.md").write_text("staged\n", encoding="utf-8")
    run_command(["git", "add", "README.md"], cwd=repo, check=True)
    (repo / "new.cpp").write_text("int value;   \n", encoding="utf-8")
    cached_before = run_command(
        ["git", "diff", "--cached", "--binary", "HEAD", "--"],
        cwd=repo,
        check=True,
    ).stdout

    whitespace = run_command(
        [
            "bash",
            str(runner),
            "git",
            "diff",
            "--cached",
            "--check",
            "HEAD",
            "--",
        ],
        cwd=repo,
    )
    listed = run_command(
        [
            "bash",
            str(runner),
            "git",
            "ls-files",
            "--error-unmatch",
            "new.cpp",
        ],
        cwd=repo,
        check=True,
    )

    assert not whitespace.ok
    assert "new.cpp:1: trailing whitespace" in whitespace.stdout
    assert listed.stdout.strip() == "new.cpp"
    assert run_command(
        ["git", "diff", "--cached", "--binary", "HEAD", "--"],
        cwd=repo,
        check=True,
    ).stdout == cached_before
    assert "?? new.cpp" in run_command(
        ["git", "status", "--short"], cwd=repo, check=True
    ).stdout


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
    remote = tmp_path / "origin.git"
    run_command(["git", "init", "--bare", str(remote)], cwd=tmp_path, check=True)
    run_command(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    run_command(
        ["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True
    )
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
    assert saved_integration.worktree_path is not None
    assert saved_integration.branch_name is not None
    assert not saved_integration.worktree_path.exists()
    assert saved_integration.transcript_path is not None
    transcript = saved_integration.transcript_path.read_text(encoding="utf-8")
    assert "start: Integration run" in transcript
    assert "validation: passed: fake" in transcript
    assert "local_only: external writes disabled" in transcript
    assert "local-only integration commit" in saved_source.summary
    local_commit = saved_integration.summary.removeprefix(
        "local-only integration commit "
    )
    assert (
        git_branch_head(config.repo_root, saved_integration.branch_name)
        == local_commit
    )
    assert remote_text == "hello\n"
    assert any(event.kind == "integration.local_only" for event in store.events(source.id))
    assert any(
        event.kind == "integration.commit_message_generated"
        for event in store.events(source.id)
    )
    assert not any(event.kind == "main.pushed" for event in store.events(source.id))


def test_integration_manager_blocks_frozen_path_before_commit(
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
            "local_only": False,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
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
        "printf '%s\\n' '{\"subject\":\"fix(docs): update integration fixture\",\"body\":\"Update README only.\\n\\nChanged files:\\n- README.md\\n\\nValidation:\\n- fake: passed\"}' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("integration source\n", encoding="utf-8")
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
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    def fail_commit(_self, _path, _message, _body="", *, expected_tree=None):
        pytest.fail("commit should not run after a frozen path change")

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    monkeypatch.setattr(
        "coquic_steward.execution.worktree.Worktrees.commit_all", fail_commit
    )

    assert not StewardExecutor(config, store).run_task(integration.id)

    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    remote_text = subprocess.run(
        ["git", "show", "origin/main:README.md"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert saved_source.status == TaskStatus.blocked
    assert saved_integration.status == TaskStatus.blocked
    assert saved_source.summary == "frozen paths changed: flake.nix"
    assert saved_integration.summary == "frozen paths changed: flake.nix"
    assert remote_text == "hello\n"
    assert any(event.kind == "path_policy.blocked" for event in store.events(source.id))


def test_integration_manager_blocks_frozen_path_before_validation_repair(
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
            "local_only": False,
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.feature.value: ("flake.nix",)}
            ),
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
        "printf 'unexpected repair\\n' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="T",
            prompt="P",
        )
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("integration source\n", encoding="utf-8")
    source.worktree_path = worktree
    source.branch_name = branch
    source.patch_path = config.patches_dir / f"{source.id}.patch"
    source.spec.metadata["worker_thread_id"] = "worker-thread-1"
    Worktrees(config).save_patch(worktree, source.patch_path)
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
                "source_patch_path": str(source.patch_path),
                "dedupe_key": f"integration:{source.id}",
            },
        ),
        dedupe_key=f"integration:{source.id}",
    )

    def fake_gates(_config, task_id, cwd):
        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("failed\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"],
                cwd=cwd,
                passed=False,
                exit_code=1,
                output_path=output,
                summary="failed",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert not StewardExecutor(config, store).run_task(integration.id)

    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    events = store.events(source.id)

    assert saved_source.status == TaskStatus.blocked
    assert saved_integration.status == TaskStatus.blocked
    assert saved_source.summary == "frozen paths changed: flake.nix"
    assert saved_integration.summary == "frozen paths changed: flake.nix"
    assert any(event.kind == "path_policy.blocked" for event in events)
    assert not any(event.kind == "integration.validation_failed" for event in events)
    assert not any(event.kind == "worker.validation_revision_requested" for event in events)
    assert not any(event.kind == "integration.retry_requested" for event in events)


def test_integration_manager_counts_main_push_budget_per_utc_day(
    config: StewardConfig, tmp_path: Path
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "integration_mode": IntegrationMode.push_main.value,
            "limits": StewardLimits(
                max_active_tasks=config.limits.max_active_tasks,
                max_main_pushes_per_day=1,
                worker_timeout_minutes=config.limits.worker_timeout_minutes,
                review_timeout_minutes=config.limits.review_timeout_minutes,
                validation_timeout_minutes=config.limits.validation_timeout_minutes,
                stale_task_minutes=config.limits.stale_task_minutes,
            ),
        }
    )
    store = TaskStore(config.db_path)
    old_push_time = utc_now().astimezone(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) - timedelta(seconds=1)
    with Session(store.engine) as session, session.begin():
        session.add(
            EventRow(
                task_id="old-integration",
                kind="main.pushed",
                message="old-sha",
                created_at=old_push_time.isoformat(),
                data_json="{}",
            )
        )
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    patch_path = tmp_path / "source.patch"
    patch_path.write_text("", encoding="utf-8")
    source.patch_path = patch_path
    store.save(source)
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate T",
            prompt="Integrate",
            metadata={"source_task_id": source.id},
        )
    )
    transcript_messages: list[tuple[str, str]] = []

    class Transcript:
        def write(self, stage: str, message: str) -> None:
            transcript_messages.append((stage, message))

    executor = StewardExecutor(config, store)

    assert executor._integration_preflight(integration, source, Transcript()) is None
    assert ("patch", f"source patch: {patch_path}") in transcript_messages

    store.add_event("today-integration", "main.pushed", "today-sha")

    assert executor._integration_preflight(integration, source, Transcript()) is False
    assert store.get(integration.id).status == TaskStatus.blocked
    assert store.get(source.id).status == TaskStatus.blocked


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
    real_push = Worktrees.push_head_to_main
    push_attempts = 0
    push_delays: list[float] = []

    def transient_push(self, path):
        nonlocal push_attempts
        push_attempts += 1
        if push_attempts == 1:
            raise RuntimeError("Could not resolve host: github.com")
        return real_push(self, path)

    monkeypatch.setattr(Worktrees, "push_head_to_main", transient_push)
    monkeypatch.setattr(
        "coquic_steward.execution.executor.time.sleep",
        lambda delay: push_delays.append(delay),
    )

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
    assert pushed_integration.branch_name is not None
    assert not pushed_integration.worktree_path.exists()
    assert not git_branch_exists(config.repo_root, pushed_integration.branch_name)
    assert remote_text == "integrated\n"
    assert remote_commit_message.startswith("fix(docs): describe integration output\n")
    assert "Source task: source-task" in remote_commit_message
    assert (
        f"Steward-Task: {source.id}"
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
    retry_event = next(
        event
        for event in store.events(source.id)
        if event.kind == "integration.push_retry"
    )
    assert retry_event.data["attempt"] == 1
    assert push_attempts == 2
    assert push_delays == [5.0]
    assert any(event.kind == "main.pushed" for event in store.events(source.id))


def test_integration_manager_preserves_branch_when_push_fails(
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
        "printf '%s\\n' '{\"subject\":\"fix(docs): keep failed push commit\",\"body\":\"Keep the integration commit available when pushing fails.\\n\\nChanged files:\\n- README.md\\n\\nValidation:\\n- fake: passed\\n\\nSource task: source-task\"}' > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("push failure integration\n", encoding="utf-8")
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
    push_attempts = 0
    push_delays: list[float] = []

    def fail_transient_push(_self, _path):
        nonlocal push_attempts
        push_attempts += 1
        raise RuntimeError("Could not resolve host: github.com")

    monkeypatch.setattr(Worktrees, "push_head_to_main", fail_transient_push)
    monkeypatch.setattr(
        "coquic_steward.execution.executor.time.sleep",
        lambda delay: push_delays.append(delay),
    )

    assert not StewardExecutor(config, store).run_task(integration.id)
    failed_source = store.get(source.id)
    failed_integration = store.get(integration.id)
    push_event = next(
        event
        for event in store.events(source.id)
        if event.kind == "integration.push_failed"
    )

    assert failed_source.status == TaskStatus.failed
    assert failed_integration.status == TaskStatus.failed
    assert failed_integration.summary == "push failed"
    assert failed_integration.worktree_path is not None
    assert failed_integration.branch_name is not None
    assert not failed_integration.worktree_path.exists()
    assert (
        git_branch_head(config.repo_root, failed_integration.branch_name)
        == push_event.data["commit"]
    )
    retry_events = [
        event
        for event in store.events(source.id)
        if event.kind == "integration.push_retry"
    ]
    assert push_attempts == 3
    assert push_delays == [5.0, 20.0]
    assert len(retry_events) == 2
    assert push_event.data["retry_count"] == 2
    assert push_event.data["retryable"] is True
    assert not any(event.kind == "main.pushed" for event in store.events(source.id))


def test_push_retry_classification_excludes_remote_rejection() -> None:
    assert _is_transient_push_failure("Could not resolve host: github.com")
    assert _is_transient_push_failure("unexpected status 503 Service Unavailable")
    assert not _is_transient_push_failure("remote rejected: permission denied")
    assert not _is_transient_push_failure("non-fast-forward update rejected")


def test_integration_manager_closes_feature_issue_after_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=config.repo_root, check=True)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=config.repo_root, check=True)
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf '%s\\n' '{\"subject\":\"feat(api): add datagram sender\",\"body\":\"Add the datagram sender requested by the selected issue.\\n\\nChanged files:\\n- README.md\\n\\nValidation:\\n- fake: passed\\n\\nSource task: source-task\"}' > \"$last\"\n",
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
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Implement #42 Add QUIC DATAGRAM send API",
            prompt="P",
            metadata={
                "source_context": {
                    "selected_signal_items": [
                        {
                            "id": "wi-feature-42",
                            "provider": "github-issues:features",
                            "kind": "github-issues.feature-request",
                            "payload": {
                                "issue_number": 42,
                                "issue_url": "https://github.com/minhuw/coquic/issues/42",
                            },
                        }
                    ]
                }
            },
        )
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("feature integrated\n", encoding="utf-8")
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
            title="Integrate feature",
            prompt="Integrate",
            metadata={"source_task_id": source.id, "dedupe_key": f"integration:{source.id}"},
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

    commands: list[list[str]] = []

    def fake_run_command(command, cwd, *, timeout=None, **_kwargs):
        commands.append(command)
        return CommandResult(command, cwd, 0, "", "")

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", fake_run_command)

    assert StewardExecutor(config, store).run_task(integration.id)

    comment = next(command for command in commands if command[:3] == ["gh", "issue", "comment"])
    close = next(command for command in commands if command[:3] == ["gh", "issue", "close"])
    assert comment[:6] == ["gh", "issue", "comment", "42", "-R", "minhuw/coquic"]
    assert "Source task: " + source.id in comment[comment.index("--body") + 1]
    assert close == [
        "gh",
        "issue",
        "close",
        "42",
        "-R",
        "minhuw/coquic",
        "--reason",
        "completed",
    ]
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))


def test_integration_manager_keeps_push_when_feature_issue_close_fails(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    source = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="P",
            metadata={
                "source_context": {
                    "selected_signal_items": [
                        {
                            "kind": "github-issues.feature-request",
                            "payload": {"issue_number": 42},
                        }
                    ]
                }
            },
        )
    )
    task = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate",
            prompt="P",
        )
    )
    store = TaskStore(config.db_path)
    saved_source, _ = store.add_task(source.spec)
    saved_task, _ = store.add_task(task.spec)
    transcript_messages: list[tuple[str, str]] = []

    class Transcript:
        def write(self, stage: str, message: str) -> None:
            transcript_messages.append((stage, message))

    def fake_run_command(command, cwd, *, timeout=None, **_kwargs):
        return CommandResult(command, cwd, 1, "", "api unavailable")

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", fake_run_command)

    StewardExecutor(config, store)._update_feature_issues_after_push(
        saved_task, saved_source, "abc123", Transcript()
    )

    assert ("issue_update_failed", "#42 comment: api unavailable") in transcript_messages
    event = next(
        event
        for event in store.events(saved_source.id)
        if event.kind == "github.issue_update_failed"
    )
    assert event.data["issue_number"] == 42
    assert event.data["step"] == "comment"


def test_integration_manager_skips_feature_issue_close_for_multiple_issues(
    config: StewardConfig, monkeypatch
) -> None:
    source = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature",
            prompt="P",
            metadata={
                "source_context": {
                    "selected_signal_items": [
                        {
                            "kind": "github-issues.feature-request",
                            "payload": {"issue_number": 42},
                        },
                        {
                            "kind": "github-issues.feature-request",
                            "payload": {"issue_number": 43},
                        },
                    ]
                }
            },
        )
    )
    task = TaskRecord(
        spec=TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate",
            prompt="P",
        )
    )
    store = TaskStore(config.db_path)
    saved_source, _ = store.add_task(source.spec)
    saved_task, _ = store.add_task(task.spec)
    transcript_messages: list[tuple[str, str]] = []

    class Transcript:
        def write(self, stage: str, message: str) -> None:
            transcript_messages.append((stage, message))

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_command",
        lambda *_args, **_kwargs: pytest.fail("issue close should be skipped"),
    )

    StewardExecutor(config, store)._update_feature_issues_after_push(
        saved_task, saved_source, "abc123", Transcript()
    )

    assert transcript_messages == [
        (
            "issue_update_skipped",
            "multiple selected feature issues; skipping automatic close",
        )
    ]
    event = next(
        event
        for event in store.events(saved_source.id)
        if event.kind == "github.issue_update_skipped"
    )
    assert event.data["issue_count"] == 2


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
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'case "$last" in\n'
        '  */reviewer-*) mode=review;;\n'
        '  */worker-integration-revision-*) mode=revision;;\n'
        "esac\n"
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
    call_log = calls.read_text(encoding="utf-8")
    assert "resume" not in call_log
    assert "worker-integration-revision-1" in call_log


def test_integration_reset_failure_blocks_without_conflict_repair(
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
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, _ = Worktrees(config).create(source)
    (worktree / "README.md").write_text("reset failure change\n", encoding="utf-8")
    source = store.get(source.id)
    source.worktree_path = worktree
    source.patch_path = config.patches_dir / source.id / "iteration-0.patch"
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

    def fail_reset(_self, _path):
        raise RuntimeError("git fetch origin main failed")

    monkeypatch.setattr(
        "coquic_steward.execution.worktree.Worktrees.reset_to_main",
        fail_reset,
    )

    assert not StewardExecutor(config, store).run_task(integration.id)
    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    events = store.events(source.id)

    assert saved_source.status == TaskStatus.blocked
    assert saved_source.summary == "integration reset failed"
    assert saved_integration.status == TaskStatus.blocked
    assert saved_integration.summary == "integration reset failed"
    assert any(event.kind == "integration.reset_failed" for event in events)
    assert not any(event.kind == "integration.conflict" for event in events)
    assert not any(
        event.kind == "worker.integration_revision_requested" for event in events
    )


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
    call_log = calls.read_text(encoding="utf-8")
    assert "resume" not in call_log
    assert "worker-integration-revision-1" in call_log


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
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'case "$last" in\n'
        '  */reviewer-*) mode=review;;\n'
        '  */worker-validation-revision-*) mode=revision;;\n'
        "esac\n"
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
    call_log = calls.read_text(encoding="utf-8")
    assert "resume" not in call_log
    assert "worker-validation-revision-1" in call_log
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

    def fail_commit(_self, _path, _message, _body="", *, expected_tree=None):
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
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'case "$last" in\n'
        '  */reviewer-*) mode=review;;\n'
        '  */worker-revision-*) mode=revision;;\n'
        "esac\n"
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
    assert "resume" not in call_log
    assert "worker-thread-1" not in call_log
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
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'case "$last" in\n'
        '  */reviewer-*) mode=review;;\n'
        '  */worker-validation-revision-*) mode=validation;;\n'
        "esac\n"
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
    assert "resume" not in call_log
    assert "worker-thread-1" not in call_log
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


def test_executor_blocks_unchanged_validation_revision(
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
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$mode" = "revision" ]; then\n'
        "  printf 'toolchain failure is external\\n' > \"$last\"\n"
        "else\n"
        "  printf 'bad patch\\n' > README.md\n"
        "  printf 'initial done\\n' > \"$last\"\n"
        "  printf '{\"type\":\"thread.started\",\"thread_id\":\"worker-thread-1\"}\\n'\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    gate_runs = 0

    def fake_gates(_config, task_id, cwd, *, label=None):
        nonlocal gate_runs
        gate_runs += 1
        output = _config.logs_dir / task_id / (label or "legacy") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("toolchain failed\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-validation"],
                cwd=cwd,
                passed=False,
                exit_code=1,
                output_path=output,
                summary="toolchain failed",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert not StewardExecutor(config, store).run_task(task.id)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert "validation revision 1 produced no patch changes" in saved.summary
    assert "fake-validation exited 1: toolchain failed" in saved.summary
    assert gate_runs == 2
    assert len(calls.read_text(encoding="utf-8").splitlines()) == 2
    assert [item.iteration for item in store.iterations(task.id)] == [0, 1]
    events = store.events(task.id)
    stalled = [event for event in events if event.kind == "validation.revision_stalled"]
    assert len(stalled) == 1
    assert stalled[0].data["reason"] == "produced no patch changes"


def test_validation_failure_state_uses_complete_validation_log(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.repo_root
    store.save(task)
    (config.repo_root / "README.md").write_text("changed\n", encoding="utf-8")
    output = tmp_path / "validation.txt"
    validation = ValidationResult(
        command=["fake-validation"],
        cwd=config.repo_root,
        passed=False,
        exit_code=1,
        output_path=output,
        summary="coquic lint shell ready",
    )
    executor = StewardExecutor(config, store)
    executor._latest_failed_validations[task.id] = [validation]

    output.write_text("STDOUT: banner\nSTDERR: first failure\n", encoding="utf-8")
    first_state = executor._validation_failure_state(task.id)
    output.write_text("STDOUT: banner\nSTDERR: second failure\n", encoding="utf-8")
    second_state = executor._validation_failure_state(task.id)
    output.write_text(
        "STDOUT: banner\n"
        "STDERR: second failure\n"
        "error (ignored): SQLite database '/tmp/eval.sqlite' is busy\n",
        encoding="utf-8",
    )

    assert first_state[0] == second_state[0]
    assert first_state[1] != second_state[1]
    assert second_state == executor._validation_failure_state(task.id)


def test_validation_failure_state_includes_untracked_changes(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.repo_root
    store.save(task)
    (config.repo_root / "README.md").write_text("changed\n", encoding="utf-8")
    output = tmp_path / "validation.txt"
    output.write_text("same failure\n", encoding="utf-8")
    validation = ValidationResult(
        command=["fake-validation"],
        cwd=config.repo_root,
        passed=False,
        exit_code=1,
        output_path=output,
        summary="same failure",
    )
    executor = StewardExecutor(config, store)
    executor._latest_failed_validations[task.id] = [validation]

    before = executor._validation_failure_state(task.id)
    (config.repo_root / "repair.txt").write_text("progress\n", encoding="utf-8")
    after = executor._validation_failure_state(task.id)

    assert before[0] != after[0]
    assert before[1] == after[1]


def test_validation_failure_state_normalizes_volatile_zig_test_output(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.repo_root
    store.save(task)
    (config.repo_root / "README.md").write_text("changed\n", encoding="utf-8")
    output = tmp_path / "zig-build-test.txt"
    validation = ValidationResult(
        command=["nix", "develop", "-c", "zig", "build", "test"],
        cwd=config.repo_root,
        passed=False,
        exit_code=1,
        output_path=output,
        summary="1 FAILED TEST",
    )
    executor = StewardExecutor(config, store)
    executor._latest_failed_validations[task.id] = [validation]

    output.write_text(
        "[       OK ] OtherSuite.PassingTest (1 ms)\n"
        "/repo/test.cpp:42: Failure\n"
        "Expected equality of these values:\n  actual\n  expected\n"
        "[  FAILED  ] Suite.FailingTest (3 ms)\n"
        "[==========] 2 tests ran. (9 ms total)\n"
        "error (ignored): SQLite database '/tmp/first.sqlite' is busy\n"
        "failed command: ./.zig-cache/o/aaaaaaaa/test\n"
        "--seed 0x11111111 -Zaaaaaaaa test\n",
        encoding="utf-8",
    )
    first_state = executor._validation_failure_state(task.id)
    output.write_text(
        "[       OK ] DifferentSuite.OtherPassingTest (17 ms)\n"
        "/repo/test.cpp:42: Failure\n"
        "Expected equality of these values:\n  actual\n  expected\n"
        "[  FAILED  ] Suite.FailingTest (21 ms)\n"
        "[==========] 2 tests ran. (35 ms total)\n"
        "error (ignored): SQLite database '/tmp/second.sqlite' is busy\n"
        "failed command: ./.zig-cache/o/bbbbbbbb/test\n"
        "--seed 0x22222222 -Zbbbbbbbb test\n",
        encoding="utf-8",
    )

    second_state = executor._validation_failure_state(task.id)
    assert first_state == second_state

    output.write_text(
        output.read_text(encoding="utf-8").replace("  actual\n", "  different\n"),
        encoding="utf-8",
    )
    assert second_state != executor._validation_failure_state(task.id)


def test_executor_revalidates_unchanged_revision_after_gate_repairs_patch(
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
        "  printf '{\"verdict\":\"approve\",\"summary\":\"ok\",\"findings\":[],\"validation_gaps\":[],\"remaining_risk\":\"\"}\\n' > \"$last\"\n"
        'elif [ "$mode" = "revision" ]; then\n'
        "  printf 'validation revision done\\n' > \"$last\"\n"
        "else\n"
        "  printf 'unformatted\\n' > README.md\n"
        "  printf 'initial done\\n' > \"$last\"\n"
        "  printf '{\"type\":\"thread.started\",\"thread_id\":\"worker-thread-1\"}\\n'\n"
        "fi\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    gate_runs = 0

    def fake_gates(_config, task_id, cwd, *, label=None):
        nonlocal gate_runs
        gate_runs += 1
        output = _config.logs_dir / task_id / (label or "legacy") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        if gate_runs == 1:
            (cwd / "README.md").write_text("formatted\n", encoding="utf-8")
        passed = gate_runs > 1
        output.write_text("ok\n" if passed else "formatted files\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-format"],
                cwd=cwd,
                passed=passed,
                exit_code=0 if passed else 1,
                output_path=output,
                summary="ok" if passed else "formatted files",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert StewardExecutor(config, store).run_task(task.id)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert saved.patch_path is not None
    assert "formatted" in saved.patch_path.read_text(encoding="utf-8")
    assert gate_runs == 2
    assert not any(
        event.kind == "validation.revision_stalled" for event in store.events(task.id)
    )


def test_executor_blocks_repeated_patch_and_validation_failure(
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
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'case "$last" in\n'
        "  */worker-validation-revision-1/*) printf 'patch-b\\n' > README.md ;;\n"
        "  */worker-validation-revision-2/*) printf 'patch-a\\n' > README.md ;;\n"
        "  *)\n"
        "    printf 'patch-a\\n' > README.md\n"
        "    printf '{\"type\":\"thread.started\",\"thread_id\":\"worker-thread-1\"}\\n'\n"
        "    ;;\n"
        "esac\n"
        "printf '%s\\n' \"$mode done\" > \"$last\"\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    gate_runs = 0

    def fake_gates(_config, task_id, cwd, *, label=None):
        nonlocal gate_runs
        gate_runs += 1
        output = _config.logs_dir / task_id / (label or "legacy") / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("same failure\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-validation"],
                cwd=cwd,
                passed=False,
                exit_code=1,
                output_path=output,
                summary="same failure",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)

    assert not StewardExecutor(config, store).run_task(task.id)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert "validation revision 2 repeated a prior patch and failure" in saved.summary
    assert gate_runs == 3
    assert [item.iteration for item in store.iterations(task.id)] == [0, 1, 2]
    events = store.events(task.id)
    stalled = [event for event in events if event.kind == "validation.revision_stalled"]
    assert len(stalled) == 1
    assert stalled[0].data["reason"] == "repeated a prior patch and failure"


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
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'case "$last" in\n'
        '  */reviewer-*) mode=review;;\n'
        '  */worker-validation-revision-*|*/worker-revision-*) mode=revision;;\n'
        "esac\n"
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


def test_cli_plan_supersedes_stale_signals_before_planning(
    repo: Path, monkeypatch
) -> None:
    monkeypatch.chdir(repo)
    store = TaskStore(load_config().db_path)
    signal, _ = store.add_signal_item(
        SignalItem(
            id="wi-codeql-42",
            provider="code-scanning",
            kind="code-scanning.alert",
            fingerprint="wi-codeql-42",
            title="CodeQL alert 42",
            payload={"alert_number": 42},
        )
    )
    monkeypatch.setattr(
        "coquic_steward.cli.collect_signal_items", lambda _config: []
    )
    monkeypatch.setattr(
        "coquic_steward.cli.revalidate_signal_items",
        lambda _config, _items: ([], {signal.id: "source_not_open"}),
    )
    monkeypatch.setattr(
        "coquic_steward.cli.run_planner",
        lambda *_args: pytest.fail("planner should not run for stale signals"),
    )

    result = CliRunner().invoke(app, ["plan"])

    assert result.exit_code == 0
    saved = store.list_signal_items()[0]
    assert saved.status == SignalItemStatus.superseded
    assert saved.planner_run_id == "source-revalidation"


def test_cli_daemon_forever_is_headless(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    started = []

    def fake_run_forever(self) -> None:
        started.append("daemon")

    monkeypatch.setattr(
        "coquic_steward.cli.StewardDaemon.run_forever", fake_run_forever
    )

    result = CliRunner().invoke(app, ["daemon"])

    assert result.exit_code == 0
    assert started == ["daemon"]
    assert "Steward daemon stopped." in result.output
    assert "Steward Web UI" not in result.output


def test_cli_daemon_help_has_no_web_options() -> None:
    result = CliRunner().invoke(app, ["daemon", "--help"])

    assert result.exit_code == 0
    assert "--web" not in result.output
    assert "--no-web" not in result.output


def test_cli_rejects_removed_web_command() -> None:
    result = CliRunner().invoke(app, ["web"])

    assert result.exit_code != 0
    assert "No such command 'web'" in result.output


def test_cli_daemon_once_is_headless(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)

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


def test_runtime_has_raw_archive_peers(config: StewardConfig) -> None:
    config.ensure_dirs()
    assert config.tasks_dir.parent == config.control_loop_dir.parent
    assert config.control_loop_dir.name == "control-loop"
    assert config.tasks_dir.name == "tasks"


def test_store_initializes_private_control_loop_ledger(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    assert isinstance(store.control_loop_ledger, ControlLoopLedger)
    assert store.control_loop_ledger.epoch_id == config.ensure_epoch()["epochId"]


def test_archive_rejects_symlink_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "control-loop"
    root.symlink_to(target, target_is_directory=True)
    with pytest.raises((ValueError, RuntimeError)):
        ControlLoopArchive(root)

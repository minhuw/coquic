from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from urllib.request import (
    BaseHandler,
    HTTPDefaultErrorHandler,
    HTTPErrorProcessor,
    OpenerDirector,
)

import pytest
from sqlalchemy import event
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
from coquic_steward.execution import SessionSupervisor, StewardExecutor, Worktrees
from coquic_steward.execution.session import FreshPlannerSession
from coquic_steward.execution.executor import (
    _is_transient_push_failure,
    commit_message_schema_path,
    frozen_patch_paths,
    parse_commit_message,
    render_commit_message_prompt,
)
from coquic_steward.execution.worktree import (
    PATH_POLICY_STATUS_PARSE_SUMMARY,
    _PathPolicyStatusParseError,
    _changed_paths_from_porcelain,
)
from coquic_steward.execution.review import (
    parse_review,
    render_review_revision_prompt,
    review_approved,
    review_schema_path,
)
from coquic_steward.execution.validation import (
    MAX_VALIDATION_OUTPUT_BYTES,
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


def _drive_durable(
    executor: StewardExecutor,
    task_id: str,
    *,
    max_steps: int = 128,
    finalize: bool = False,
) -> bool:
    """Advance one task through persisted phases with a bounded driver."""

    for _ in range(max_steps):
        outcome = executor.advance_once(task_id)
        if outcome.status in {"ready_to_seal", "terminal", "blocked"}:
            if finalize:
                StewardDaemon(executor.config, executor.store).finalize_terminal_task(task_id)
            return outcome.status in {"ready_to_seal", "terminal"}
        if outcome.status == "in_progress":
            continue
        if not outcome.progressed and outcome.next_phase is None:
            return False
    raise AssertionError(f"durable task did not reach a stopping point: {task_id}")


def _advance_durable(
    executor: StewardExecutor, task_id: str, steps: int
) -> list[object]:
    return [executor.advance_once(task_id) for _ in range(steps)]


def _durable_codex(
    tmp_path: Path,
    *,
    change: str = "changed by durable pipeline",
    review: str = '{"verdict":"approve","summary":"ok","findings":[],"validation_gaps":[],"remaining_risk":""}',
    commit: str = '{"subject":"fix: durable pipeline","body":"persist the accepted durable tree"}',
) -> Path:
    fake = tmp_path / "durable-codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "case \"$last\" in\n"
        f"  */reviewer-*) printf '%s\\n' '{review}' > \"$last\" ;;\n"
        f"  */commit-message-*) printf '%s\\n' '{commit}' > \"$last\" ;;\n"
        f"  *) printf '%s\\n' '{change}' > README.md; printf 'done\\n' > \"$last\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def _passing_durable_gates(
    config,
    task_id,
    cwd,
    *,
    label=None,
    on_gate_start=None,
    on_gate_result=None,
    command_runner=None,
):
    output = config.logs_dir / task_id / (label or "durable") / "gate.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("ok\\n", encoding="utf-8")
    return [
        ValidationResult(
            command=["fake-gate"], cwd=cwd, passed=True, exit_code=0, output_path=output
        )
    ]


def _durable_push_setup(
    config: StewardConfig,
    tmp_path: Path,
    monkeypatch,
    *,
    issue_numbers: tuple[int, ...] = (),
    local_only: bool = False,
    frozen_paths: tuple[str, ...] = (),
):
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    subprocess.run(
        ["git", "push", "-u", "origin", "main"],
        cwd=config.repo_root,
        check=True,
    )
    fake = _durable_codex(tmp_path, change="durable push change")
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "git_remote": "origin",
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": local_only,
            "path_policy": (
                PathPolicyConfig(
                    frozen_by_kind={TaskKind.integration.value: frozen_paths}
                )
                if frozen_paths
                else config.path_policy
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    selected = [
        {
            "kind": "github-issues.feature-request",
            "payload": {"issue_number": number},
        }
        for number in issue_numbers
    ]
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature source",
            prompt="Implement the selected feature",
            metadata={"source_context": {"selected_signal_items": selected}},
        )
    )
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate feature",
            prompt="Integrate the feature",
            metadata={"source_task_id": source.id},
        )
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )
    return config, store, source, integration, StewardExecutor(config, store)


def ingest_test_signal(
    store: TaskStore,
    item: SignalItem,
    *,
    suppression_hours: int = 24,
) -> tuple[SignalItem, bool]:
    saved, _signals, created = store.ingest_signal_collection(
        SignalFetchRun(
            id=new_signal_fetch_id(),
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
        suppression_hours=suppression_hours,
    )
    return saved[0], bool(created)


def test_config_defaults_from_repo(repo: Path, coquic_home: Path) -> None:
    config = load_config(repo_root=repo)
    assert config.repo_root == repo
    assert config.steward_home == coquic_home / "steward"
    assert config.state_dir == coquic_home / "steward"
    assert config.db_path == coquic_home / "steward.sqlite"
    assert config.db_path.name == "steward.sqlite"
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
    store = TaskStore.create(config.db_path)
    spec = TaskSpec(
        kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P"
    )

    first, created = store.add_task(spec, dedupe_key="same")
    second, duplicate_created = store.add_task(spec, dedupe_key="same")

    assert created
    assert not duplicate_created
    assert first.id == second.id
    assert store.get(first.id).status == TaskStatus.queued


def test_store_notifies_after_task_state_change(config: StewardConfig) -> None:
    changes = 0

    def on_change() -> None:
        nonlocal changes
        changes += 1

    store = TaskStore.create(config.db_path, on_change=on_change)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    before = changes

    store.start_worker(task.id, "worker started")

    assert changes > before
    assert store.get(task.id).status == TaskStatus.running


def test_daemon_marks_dispatch_exception_failed(config: StewardConfig, monkeypatch) -> None:
    store = TaskStore.create(config.db_path)
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

    monkeypatch.setattr(StewardExecutor, "advance_once", fail_after_start)

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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fail_before_start(self, _task_id: str) -> bool:
        raise RuntimeError("codex failed before start")

    monkeypatch.setattr(StewardExecutor, "advance_once", fail_before_start)

    result = StewardDaemon(config, store).tick(plan=False, max_dispatch=1)

    saved = store.get(task.id)
    assert result.skipped == 1
    assert saved.status == TaskStatus.failed
    assert saved.summary == "dispatch failed: codex failed before start"
    assert any(event.kind == "dispatch.failed" for event in store.events(task.id))


def test_store_touches_only_active_tasks(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    with pytest.raises(InvalidTaskTransition):
        store.start_review(task.id, "review started")

    assert store.get(task.id).status == TaskStatus.queued


def test_store_allows_integration_conflict_to_return_to_worker(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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


def test_store_dispatch_snapshot_is_bounded_and_deterministic(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)

    def add(
        task_id: str,
        *,
        worker: WorkerKind,
        kind: TaskKind,
        priority: Priority,
    ) -> TaskRecord:
        task, _ = store.add_task(
            TaskSpec(
                id=task_id,
                kind=kind,
                worker=worker,
                title=task_id,
                prompt=task_id,
                priority=priority,
            )
        )
        return task

    integration_b = add(
        "task-integration-b",
        worker=WorkerKind.integration_manager,
        kind=TaskKind.integration,
        priority=Priority.high,
    )
    integration_a = add(
        "task-integration-a",
        worker=WorkerKind.integration_manager,
        kind=TaskKind.integration,
        priority=Priority.high,
    )
    source_b = add(
        "task-source-b",
        worker=WorkerKind.custom,
        kind=TaskKind.custom,
        priority=Priority.urgent,
    )
    source_a = add(
        "task-source-a",
        worker=WorkerKind.custom,
        kind=TaskKind.custom,
        priority=Priority.urgent,
    )
    active_source = add(
        "task-active-source",
        worker=WorkerKind.custom,
        kind=TaskKind.custom,
        priority=Priority.low,
    )
    store.start_worker(active_source.id, "running")
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE tasks SET created_at = ? WHERE id IN (?, ?, ?, ?, ?)",
            (
                "2026-01-01T00:00:00+00:00",
                integration_b.id,
                integration_a.id,
                source_b.id,
                source_a.id,
                active_source.id,
            ),
        )

    snapshot = store.dispatch_snapshot(
        source_limit=1,
        integration_limit=2,
        resumable_limit=1,
    )

    assert [task.id for task in snapshot.queued] == [
        integration_a.id,
        integration_b.id,
        source_a.id,
    ]
    assert [task.id for task in snapshot.resumable] == [active_source.id]
    assert snapshot.source_active == 1
    assert snapshot.integration_active == 0
    assert source_b.id not in {task.id for task in snapshot.queued}


def test_store_tracks_signal_items_independently(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    item, created = ingest_test_signal(
        store,
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
    duplicate, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-duplicate",
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


def test_store_preserves_repository_relative_signal_paths(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    expected_path = "steward/src/coquic_steward/public_mirror.py"
    ingest_test_signal(
        store,
        SignalItem(
            provider="codacy",
            kind="codacy.issue",
            fingerprint="codacy-public-mirror",
            title="Codacy issue",
            location={"path": expected_path, "line": 203},
        )
    )

    reopened = TaskStore.open(config.db_path)

    pending = reopened.pending_signal_items()
    assert len(pending) == 1
    assert pending[0].location == {"path": expected_path, "line": 203}


def test_store_records_scheduler_wakeups_for_actionable_changes(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, created = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    item, item_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-codacy-1",
            provider="codacy",
            kind="codacy.issue",
            fingerprint="same-finding",
            title="Open Codacy finding",
        )
    )
    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
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

    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.ci, worker=WorkerKind.ci_doctor, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
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
    with Session(store.engine) as session:
        first_row = session.get(SignalItemRow, first.id)
        assert first_row is not None
        assert first_row.workflow_run_id == "100"
        assert first_row.workflow_run_attempt == 1
        assert json.loads(first_row.payload_json) == {"run_id": "100"}
    store.mark_signal_items_planned(
        [first.id], planner_run_id="planner-1", task_id=task.id
    )
    store.finish_task(task.id, TaskStatus.no_changes, "no changes")

    same_attempt, duplicate_created = ingest_test_signal(
        store,
        SignalItem(
            id="wi-ci-stable",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="stable-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100", "run_attempt": 1},
        )
    )
    next_attempt, next_attempt_created = ingest_test_signal(
        store,
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
    with Session(store.engine) as session:
        next_row = session.get(SignalItemRow, next_attempt.id)
        assert next_row is not None
        assert next_row.workflow_run_id == "100"
        assert next_row.workflow_run_attempt == 2


@pytest.mark.parametrize(
    ("provider", "payload"),
    [
        ("github-actions:ci", {"run_attempt": 2, "evidence": {"raw": "keep"}}),
        (
            "github-actions:ci",
            {"run_id": None, "run_attempt": 2, "evidence": {"raw": "keep"}},
        ),
        (
            "github-actions:ci",
            {"run_id": 100, "run_attempt": 2, "evidence": {"raw": "keep"}},
        ),
        (
            "codacy",
            {"run_id": "100", "run_attempt": 2, "evidence": {"raw": "keep"}},
        ),
    ],
)
def test_store_keeps_invalid_or_non_workflow_signal_identity_unindexed(
    config: StewardConfig, provider: str, payload: dict[str, object]
) -> None:
    store = TaskStore.create(config.db_path)
    item, created = ingest_test_signal(
        store,
        SignalItem(
            id="identity-case",
            provider=provider,
            kind="signal.test",
            fingerprint=f"identity-{provider}",
            title="Identity case",
            payload=payload,
        )
    )

    assert created
    with Session(store.engine) as session:
        row = session.get(SignalItemRow, item.id)
        assert row is not None
        assert row.workflow_run_id is None
        assert row.workflow_run_attempt is None
        assert json.loads(row.payload_json) == payload


def test_store_matches_workflow_signal_identity_with_one_bounded_query(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    first, created = ingest_test_signal(
        store,
        SignalItem(
            id="bounded-first",
            provider="github-actions:ci",
            kind="github-actions.ci-failure",
            fingerprint="bounded-first-fingerprint",
            title="CI run 100 failed",
            payload={"run_id": "100"},
        )
    )
    assert created

    statements: list[str] = []

    def capture_statement(
        _connection, _cursor, statement, _parameters, _context, _executemany
    ) -> None:
        if "signal_items" in statement.lower():
            statements.append(statement)

    event.listen(store.engine, "before_cursor_execute", capture_statement)
    try:
        duplicate, duplicate_created = ingest_test_signal(
            store,
            SignalItem(
                id="bounded-second",
                provider="github-actions:ci",
                kind="github-actions.ci-failure",
                fingerprint="bounded-second-fingerprint",
                title="CI run 100 failed again",
                payload={"run_id": "100", "run_attempt": 1},
            )
        )
    finally:
        event.remove(store.engine, "before_cursor_execute", capture_statement)

    assert not duplicate_created
    assert duplicate.id == first.id
    signal_queries = [
        statement
        for statement in statements
        if "select" in statement.lower() and "from signal_items" in statement.lower()
    ]
    assert len(signal_queries) == 2
    identity_queries = [
        statement
        for statement in signal_queries
        if (
            "signal_items.workflow_run_id = ?" in statement
            and "signal_items.workflow_run_attempt = ?" in statement
        )
    ]
    assert len(identity_queries) == 1
    assert "limit" in identity_queries[0].lower()
    assert not any(
        "workflow_run_id" not in statement
        and "fingerprint" not in statement
        and "where signal_items.provider" in statement.lower()
        for statement in signal_queries
    )


def test_store_requeues_planned_signal_after_configured_suppression(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.finish_task(task.id, TaskStatus.failed, "failed")
    first, created = ingest_test_signal(
        store,
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

    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
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
    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    first_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T1", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
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
    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    first_task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T1", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
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
    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    first, created = ingest_test_signal(
        store,
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

    second, duplicate_created = ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
    signal, _ = ingest_test_signal(
        store,
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


def test_daemon_replans_expired_failed_signal_without_refetch(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    signal, _ = ingest_test_signal(
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


def test_store_marks_task_running_when_revision_iteration_begins(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
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

    daemon = StewardDaemon(config, TaskStore.create(config.db_path), logger=logs.append)
    daemon.startup_reconcile()

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

    daemon = StewardDaemon(config, TaskStore.create(config.db_path))
    with pytest.raises(StewardPreflightError) as exc_info:
        daemon.startup_reconcile()

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

    daemon = StewardDaemon(config, TaskStore.create(config.db_path))
    with pytest.raises(StewardPreflightError) as exc_info:
        daemon.startup_reconcile()

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

    StewardDaemon(config, TaskStore.create(config.db_path))


def test_daemon_logs_planner_lifecycle_event(
    config: StewardConfig, monkeypatch, tmp_path: Path
) -> None:
    store = TaskStore.create(config.db_path)
    inbox_item, _ = ingest_test_signal(
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
    store = TaskStore.create(config.db_path)
    lines: list[str] = []
    ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
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

    def fake_advance(task_id: str) -> SimpleNamespace:
        store.update_status(task_id, TaskStatus.succeeded, "done")
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

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
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

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
    store = TaskStore.create(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_advance(task_id: str) -> SimpleNamespace:
        task = store.get(task_id)
        if task.spec.worker == WorkerKind.integration_manager:
            store.finish_task(task.id, TaskStatus.succeeded, "integrated")
            store.finish_task(source.id, TaskStatus.succeeded, "integrated")
            return SimpleNamespace(status="terminal", progressed=True, next_phase=None)
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
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

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
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_advance(task_id: str) -> SimpleNamespace:
        store.finish_task(task_id, TaskStatus.blocked, "blocked before crash")
        raise RuntimeError("after terminal update")

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

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
    store = TaskStore.create(config.db_path)
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

    def fake_advance(task_id: str) -> SimpleNamespace:
        ran.append(task_id)
        store.update_status(task_id, TaskStatus.succeeded, "done")
        return SimpleNamespace(status="terminal", progressed=True, next_phase=None)

    daemon = StewardDaemon(config, store)
    monkeypatch.setattr(daemon.executor, "advance_once", fake_advance)

    result = daemon.tick(plan=False, dispatch=True)

    assert result.dispatched == 1
    assert ran == [source.id]
    assert store.get(queued_integration.id).status == TaskStatus.queued


def test_daemon_forever_dispatches_up_to_source_capacity_per_cycle(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    daemon = StewardDaemon(config, store)
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.wait_for_scheduler_event",
        lambda *_args, **_kwargs: SchedulerTrigger(reason="wakeup", providers=[]),
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
    store.request_wakeup("task.status", {"task_id": "task-1"})
    ingest_test_signal(
        store,
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)

    initial = scheduler_state(config, store)

    assert due_provider_names(initial) == list(config.enabled_signals)
    assert initial.idle is True
    assert set(initial.state.model_dump()) == {
        "source_active",
        "source_capacity",
        "source_queued",
        "integration_active",
        "integration_queued",
        "pending_wakeups",
        "recent_wakeups",
        "providers",
    }
    assert all(provider.due for provider in initial.state.providers)

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
    codacy = next(
        provider
        for provider in state.state.providers
        if provider.provider == "codacy"
    )

    assert codacy.due is False
    assert codacy.poll_interval_minutes == 360
    assert codacy.idle_poll_interval_minutes == 30
    assert codacy.next_due_at > codacy.last_fetch_at
    assert codacy.idle_next_due_at == codacy.last_fetch_at + timedelta(minutes=30)
    assert codacy.idle_due is False


def test_scheduler_snapshot_bounds_wakeups_and_provider_fetches(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy", "code-scanning"),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)

    for index in range(25):
        store.request_wakeup(f"scheduler-{index}")
    old_fetch = utc_now() - timedelta(hours=2)
    new_fetch = utc_now() - timedelta(minutes=1)
    for provider in config.enabled_signals:
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=old_fetch,
                completed_at=old_fetch,
            )
        )
        store.add_signal_fetch_run(
            SignalFetchRun(
                provider=provider,
                status=SignalFetchStatus.ok,
                started_at=new_fetch,
                completed_at=new_fetch,
            )
        )
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="disabled-provider",
            status=SignalFetchStatus.ok,
            started_at=new_fetch,
            completed_at=new_fetch,
        )
    )

    snapshot = store.scheduler_snapshot(config.enabled_signals)

    assert len(snapshot.pending_wakeups) == 20
    assert len(snapshot.recent_wakeups) == 20
    assert list(snapshot.latest_fetches) == list(config.enabled_signals)
    assert all(
        fetch is not None and fetch.completed_at == new_fetch
        for fetch in snapshot.latest_fetches.values()
    )
    assert all(
        left.created_at <= right.created_at
        for left, right in zip(snapshot.pending_wakeups, snapshot.pending_wakeups[1:])
    )
    assert all(
        left.created_at >= right.created_at
        for left, right in zip(snapshot.recent_wakeups, snapshot.recent_wakeups[1:])
    )


def test_scheduler_idle_excludes_signal_error_rows(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    ingest_test_signal(
        store,
        SignalItem(
            provider="codacy",
            kind="signal-error",
            fingerprint="error-only",
            title="Provider error",
        )
    )

    assert scheduler_state(config, store).idle is True

    ingest_test_signal(
        store,
        SignalItem(
            provider="codacy",
            kind="codacy.issue",
            fingerprint="ordinary-pending",
            title="Pending finding",
        )
    )

    assert scheduler_state(config, store).idle is False


def test_scheduler_idle_suppressed_by_active_source_task(
    config: StewardConfig,
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    store.update_status(task.id, TaskStatus.running, "started")

    result = scheduler_state(config, store)

    assert result.idle is False


def test_scheduler_state_uses_error_retry_timing(config: StewardConfig) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() - timedelta(minutes=2)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.error,
            started_at=fetched_at,
            completed_at=fetched_at,
            error="temporary",
        )
    )

    result = scheduler_state(config, store)
    provider = result.state.providers[0]

    retry_minutes = config.signal_providers["codacy"].error_retry_minutes
    regular_delta = provider.next_due_at - fetched_at
    assert provider.last_status == SignalFetchStatus.error
    assert timedelta(minutes=retry_minutes) <= regular_delta < timedelta(
        minutes=retry_minutes + 17
    )
    assert provider.idle_next_due_at == fetched_at + timedelta(minutes=retry_minutes)


def test_wait_for_scheduler_event_uses_one_snapshot_per_iteration(
    config: StewardConfig, monkeypatch
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "enabled_signals": ("codacy",),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    fetched_at = utc_now() + timedelta(hours=1)
    store.add_signal_fetch_run(
        SignalFetchRun(
            provider="codacy",
            status=SignalFetchStatus.ok,
            started_at=fetched_at,
            completed_at=fetched_at,
        )
    )
    snapshot_calls: list[tuple[str, ...]] = []
    original_snapshot = store.scheduler_snapshot

    def scheduler_snapshot(providers=()):
        snapshot_calls.append(tuple(providers))
        return original_snapshot(providers)

    monkeypatch.setattr(store, "scheduler_snapshot", scheduler_snapshot)

    def fail_legacy_query(*_args, **_kwargs):
        raise AssertionError("scheduler wait used a legacy store query")

    for method in (
        "source_active_count",
        "source_queued_count",
        "integration_active_count",
        "integration_queued_count",
        "pending_wakeups",
        "recent_wakeups",
        "pending_signal_items",
        "latest_signal_fetch_run",
    ):
        monkeypatch.setattr(store, method, fail_legacy_query)

    def fake_sleep(_seconds: float) -> None:
        store.request_wakeup("scheduler-test")

    monkeypatch.setattr("coquic_steward.orchestration.daemon.time.sleep", fake_sleep)

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "wakeup"
    assert snapshot_calls == [config.enabled_signals, config.enabled_signals]


def test_wait_for_scheduler_event_returns_due_providers(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)

    trigger = wait_for_scheduler_event(config, store)

    assert trigger.reason == "provider-due"
    assert trigger.providers == list(config.enabled_signals)


def test_wait_for_scheduler_event_prioritizes_pending_wakeup(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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


def test_codex_planner_selects_explicit_runner_boundaries(
    config: StewardConfig,
) -> None:
    default_planner = CodexPlanner(config)
    assert isinstance(default_planner.runner, CodexRunner)

    explicit_runner = CodexRunner(config)
    explicit_planner = CodexPlanner(config, runner=explicit_runner)
    assert explicit_planner.runner is explicit_runner

    class MethodLookalike:
        def run(self, *_args, **_kwargs):
            raise AssertionError("unsupported planner lookalike was invoked")

    class NestedRunner:
        def __init__(self) -> None:
            self.runner = explicit_runner

    with pytest.raises(TypeError, match="FreshPlannerSession"):
        CodexPlanner(config, invocation=MethodLookalike())
    with pytest.raises(TypeError, match="FreshPlannerSession"):
        CodexPlanner(config, invocation=NestedRunner())

    supervisor = SessionSupervisor(
        config,
        TaskStore.create(config.db_path),
        require_boundary=False,
    )
    with pytest.raises(TypeError, match="FreshPlannerSession"):
        CodexPlanner(config, invocation=supervisor)
    with pytest.raises(ValueError, match="either runner or invocation"):
        CodexPlanner(
            config,
            runner=explicit_runner,
            invocation=FreshPlannerSession(config),
        )


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
    store = TaskStore.create(config.db_path)
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
    task, _ = TaskStore.create(config.db_path).add_task(
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
    task, _ = TaskStore.create(config.db_path).add_task(
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
    task, _ = TaskStore.create(config.db_path).add_task(
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


def test_signal_collector_accepts_providers(config: StewardConfig) -> None:
    class FakeProvider(GitHubActionsCiProvider):
        name = "fake"

        def collect(
            self, _config: StewardConfig, *, max_items: int = 12
        ) -> ProviderSignalResult:
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
    class FailingProvider(CodacyProvider):
        name = "codacy"

        def collect(
            self, _config: StewardConfig, *, max_items: int = 12
        ) -> ProviderSignalResult:
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
    class WorkItemProvider(CodacyProvider):
        name = "codacy"

        def collect(
            self, _config: StewardConfig, *, max_items: int = 12
        ) -> ProviderSignalResult:
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
    task = TaskStore.create(config.db_path).add_task(
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
    task = TaskStore.create(config.db_path).add_task(
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
    task = TaskStore.create(config.db_path).add_task(
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
    task = TaskStore.create(config.db_path).add_task(
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
    task = TaskStore.create(config.db_path).add_task(
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
    task = TaskStore.create(config.db_path).add_task(
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(push_config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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


def test_porcelain_z_parser_preserves_structural_utf8_paths() -> None:
    output = (
        "??  leading and trailing  \0"
        " M tab\tinside\t \0"
        "?? line\nbreak\0"
        '?? "quoted -> name"\0'
        "?? directory\\name\0"
        "?? literal -> arrow\0"
        "?? leading and trailing\0"
    )

    assert _changed_paths_from_porcelain(output) == [
        "leading and trailing",
        "tab\tinside",
        "line\nbreak",
        '"quoted -> name"',
        "directory/name",
        "literal -> arrow",
    ]


@pytest.mark.parametrize("status", ["R  ", "C  "])
def test_porcelain_z_parser_returns_rename_source_then_destination(status: str) -> None:
    assert _changed_paths_from_porcelain(
        f"{status}destination -> name\0source\\name\0"
    ) == ["source/name", "destination -> name"]


@pytest.mark.parametrize(
    "output",
    ["ZZ path\0", "  path\0", "?M path\0", "!M path\0"],
)
def test_porcelain_z_parser_rejects_invalid_status_fields(output: str) -> None:
    with pytest.raises(_PathPolicyStatusParseError):
        _changed_paths_from_porcelain(output)


def test_porcelain_z_parser_rejects_truncated_records_with_bounded_diagnostic() -> None:
    output = "?? " + ("x" * 300)

    with pytest.raises(_PathPolicyStatusParseError) as raised:
        _changed_paths_from_porcelain(output)

    error = raised.value
    assert str(error) == PATH_POLICY_STATUS_PARSE_SUMMARY
    assert error.diagnostic == {
        "raw_prefix": repr(output.encode("utf-8")[:256]),
        "byte_length": len(output.encode("utf-8")),
    }


def test_porcelain_z_parser_rejects_truncated_rename_record() -> None:
    with pytest.raises(_PathPolicyStatusParseError) as raised:
        _changed_paths_from_porcelain("R  destination\0")

    assert raised.value.diagnostic == {
        "raw_prefix": repr(b"R  destination\0"),
        "byte_length": len(b"R  destination\0"),
    }


def test_git_porcelain_z_reports_rename_destination_before_source(tmp_path: Path) -> None:
    repo = tmp_path / "status-repo"
    run_command(["git", "init", "-q", str(repo)], cwd=tmp_path, check=True)
    run_command(
        ["git", "config", "user.email", "steward@example.test"],
        cwd=repo,
        check=True,
    )
    run_command(
        ["git", "config", "user.name", "Steward Test"], cwd=repo, check=True
    )
    (repo / "source name.txt").write_text("source\n", encoding="utf-8")
    run_command(["git", "add", "source name.txt"], cwd=repo, check=True)
    run_command(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    run_command(
        ["git", "mv", "source name.txt", "destination -> name.txt"],
        cwd=repo,
        check=True,
    )

    output = run_command(
        [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
        cwd=repo,
        check=True,
    ).stdout

    assert output.split("\0")[:2] == [
        "R  destination -> name.txt",
        "source name.txt",
    ]
    assert _changed_paths_from_porcelain(output) == [
        "source name.txt",
        "destination -> name.txt",
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
    task = TaskStore.create(config.db_path).add_task(
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
    store = TaskStore.create(config.db_path)
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
    task = TaskStore.create(config.db_path).add_task(
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
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'no changes\\n' > \"$last\"\\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.no_changes
    assert any(event.kind == "pipeline.ready_to_seal" for event in store.events(task.id))
    assert not any(event.kind == "pipeline.blocked" for event in store.events(task.id))

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
        'mkdir -p "$(dirname "$last")"\n'
        "printf '{}\n' > flake.nix\n"
        "printf 'changed frozen path\\n' > \"$last\"\\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.custom.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates",
        lambda *_args, **_kwargs: pytest.fail("validation should not run after a frozen path change"),
    )
    executor = StewardExecutor(config, store)
    assert not _drive_durable(executor, task.id)

    saved = store.get(task.id)
    events = store.events(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert any(event.kind == "pipeline.blocked" for event in events)

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
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'source change\n' > README.md\n"
        "printf 'changed source\\n' > \"$last\"\\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "path_policy": PathPolicyConfig(
                frozen_by_kind={TaskKind.custom.value: ("flake.nix",)}
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def fake_gates(_config, task_id, cwd, **_kwargs):
        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    executor = StewardExecutor(config, store)
    assert not _drive_durable(executor, task.id)

    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert saved.patch_path is None
    assert any(event.kind == "pipeline.blocked" for event in store.events(task.id))

@pytest.mark.parametrize("failure", ["malformed", "decode"])
def test_executor_blocks_status_parse_failure_with_fixed_summary(
    config: StewardConfig, monkeypatch, failure: str
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    worktree, branch = Worktrees(config).create(task)
    (worktree / "README.md").write_text("changed\n", encoding="utf-8")
    task.worktree_path = worktree
    task.branch_name = branch
    store.save(task)

    if failure == "malformed":
        error: BaseException = _PathPolicyStatusParseError("?? " + ("x" * 300))
    else:
        error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    def fail_status(_path: Path) -> list[str]:
        raise error

    executor = StewardExecutor(config, store)
    monkeypatch.setattr(executor.worktrees, "forbidden_paths", fail_status)

    result = executor._prepare_patch(
        task.id,
        "initial",
        iteration=0,
        no_changes_status=TaskStatus.no_changes,
    )

    assert result.value == "terminal_failure"
    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == PATH_POLICY_STATUS_PARSE_SUMMARY
    event = next(
        event for event in store.events(task.id) if event.kind == "path_policy.blocked"
    )
    if failure == "malformed":
        assert event.data["diagnostic"] == error.diagnostic
    else:
        assert "diagnostic" not in event.data


def test_executor_heartbeats_active_worker(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.setattr("coquic_steward.execution.executor.WORKER_HEARTBEAT_SECONDS", 0.01)
    store = TaskStore.create(config.db_path)
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
    fake = _durable_codex(tmp_path, change="changed by steward")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert saved.patch_path is not None
    assert "changed by steward" in saved.patch_path.read_text(encoding="utf-8")
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))
    assert any(event.kind == "pipeline.ready_to_seal" for event in store.events(task.id))

def test_executor_does_not_clean_external_finished_worktree(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore.create(config.db_path)
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
    fake = _durable_codex(tmp_path, change="changed by steward")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    observed: dict[str, object] = {}

    def fake_gates(_config, task_id, cwd, **_kwargs):
        current = store.get(task_id)
        observed["status"] = current.status
        observed["summary"] = current.summary
        observed["phase"] = next(
            event.data["phase"]
            for event in reversed(store.events(task_id))
            if event.kind == "pipeline.phase.started"
        )
        output = _config.logs_dir / task_id / "fake.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", fake_gates)
    executor = StewardExecutor(config, store)
    _advance_durable(executor, task.id, 3)

    assert observed["status"] == TaskStatus.running
    assert observed["phase"] == "validation"

def test_executor_records_validation_results_incrementally(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
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
        command_runner=None,
    ):
        assert on_gate_start is not None
        assert on_gate_result is not None
        results = []
        for position, command in enumerate((["gate-0"], ["gate-1"])):
            on_gate_start(position, f"gate-{position}.txt", command)
            output = _config.logs_dir / task_id / (label or "validation") / f"gate-{position}.txt"
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
    executor = StewardExecutor(config, store)
    _advance_durable(executor, task.id, 3)

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
    assert [json.loads(row.command_json) for row in rows][-2:] == [["gate-0"], ["gate-1"]]
    assert {row.iteration for row in rows} == {0}
    assert rows[-1].position == rows[-2].position + 1

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

    def fake_run_command(
        command, cwd, *, timeout=None, max_output_bytes=None, **_kwargs
    ):
        observed["command"] = command
        observed["cwd"] = cwd
        observed["timeout"] = timeout
        observed["max_output_bytes"] = max_output_bytes
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
        "max_output_bytes": MAX_VALIDATION_OUTPUT_BYTES,
    }
    assert result.exit_code == 124
    assert not result.passed
    assert "command timed out" in result.output_path.read_text(encoding="utf-8")


def test_executor_rejects_invalid_review_output(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path, review="not-json")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert not _drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert any(event.kind == "pipeline.review.raw" for event in store.events(task.id))
    assert any(event.kind == "pipeline.blocked" for event in store.events(task.id))

def test_executor_accepts_approved_review_with_validation_gaps(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(
        tmp_path,
        review='{"verdict":"approve","summary":"ok with gap","findings":[],"validation_gaps":["shellcheck unavailable"],"remaining_risk":"low"}',
    )
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    outcomes = _advance_durable(executor, task.id, 4)
    assert outcomes[-1].next_phase.value == "integration"
    assert any(
        event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("next_phase") == "integration"
        for event in store.events(task.id)
    )
    assert not any(event.kind == "pipeline.formality.effective" for event in store.events(task.id))

def test_executor_push_main_uses_durable_commit_phase(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "integration_mode": IntegrationMode.push_main.value,
            "local_only": True,
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.succeeded
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))
    assert not any(
        item.spec.worker == WorkerKind.integration_manager
        for item in store.list_tasks()
    )

def test_durable_local_only_commit_does_not_push_remote(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, local_only=True
    )
    assert _drive_durable(executor, integration.id)
    assert store.get(integration.id).status == TaskStatus.succeeded
    assert store.get(source.id).status == TaskStatus.queued
    remote_text = subprocess.run(
        ["git", "show", "origin/main:README.md"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert remote_text == "hello\n"
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_durable_ordinary_push_uses_task_as_issue_source(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, _integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    source.spec.kind = TaskKind.custom
    source.spec.workflow = TaskWorkflow.fix
    source.spec.worker = WorkerKind.custom
    store.save(source)
    commands: list[list[str]] = []
    real_command = run_command

    def command(argv, cwd, *, timeout=None, **_kwargs):
        if argv and argv[0] == "gh":
            commands.append(argv)
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert _drive_durable(executor, source.id), (
        f"status={store.get(source.id).status} "
        f"summary={store.get(source.id).summary} "
        f"events={[event.kind for event in store.events(source.id)]}"
    )

    assert store.get(source.id).status == TaskStatus.pushed
    assert any(event.kind == "pipeline.push" for event in store.events(source.id))
    assert [item[:3] for item in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))


def test_durable_validation_blocks_frozen_path_before_commit(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, frozen_paths=("flake.nix",)
    )

    def gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "frozen.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("ok\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return [ValidationResult(command=["fake"], cwd=cwd, passed=True, exit_code=0, output_path=output)]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    assert not _drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert not any(event.kind == "pipeline.commit" for event in store.events(integration.id))

def test_durable_validation_blocks_frozen_path_before_repair_child(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, frozen_paths=("flake.nix",)
    )

    def gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "frozen-failure.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("failed\n", encoding="utf-8")
        (cwd / "flake.nix").write_text("{}\n", encoding="utf-8")
        return [ValidationResult(command=["fake"], cwd=cwd, passed=False, exit_code=1, output_path=output)]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    assert not _drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "frozen paths changed: flake.nix"
    assert len(store.list_pipelines(integration.id)) == 1

def test_integration_status_parse_failure_blocks_only_integration_task(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="Source", prompt="P")
    )
    store.start_integration(source.id, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate Source",
            prompt="Integrate",
            metadata={"source_task_id": source.id},
        )
    )
    executor = StewardExecutor(config, store)
    failure = _PathPolicyStatusParseError("?? " + ("x" * 300))

    def fail_status(_path: Path, _task: TaskRecord) -> list[str]:
        raise failure

    monkeypatch.setattr(executor.worktrees, "frozen_paths", fail_status)
    transcript_messages: list[tuple[str, str]] = []

    class Transcript:
        def write(self, stage: str, message: str) -> None:
            transcript_messages.append((stage, message))

    assert (
        executor._block_integration_for_frozen_paths(
            integration, source, config.repo_root, Transcript()
        )
        is False
    )
    assert store.get(integration.id).status == TaskStatus.blocked
    assert store.get(integration.id).summary == PATH_POLICY_STATUS_PARSE_SUMMARY
    assert store.get(source.id).status == TaskStatus.integrating
    event = next(
        event
        for event in store.events(integration.id)
        if event.kind == "path_policy.blocked"
    )
    assert event.data["integration_task_id"] == integration.id
    assert event.data["diagnostic"] == failure.diagnostic
    assert ("path_policy_blocked", PATH_POLICY_STATUS_PARSE_SUMMARY) in transcript_messages
    assert not any(
        event.kind == "path_policy.blocked" for event in store.events(source.id)
    )


@pytest.mark.parametrize("repair", ["conflict", "validation"])
@pytest.mark.parametrize("policy", ["forbidden", "frozen"])
@pytest.mark.parametrize("failure_kind", ["malformed", "decode"])
def test_integration_repair_status_parse_failure_preserves_source(
    config: StewardConfig,
    monkeypatch,
    repair: str,
    policy: str,
    failure_kind: str,
) -> None:
    store = TaskStore.create(config.db_path)
    source, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="Source", prompt="P")
    )
    worktree, branch = Worktrees(config).create(source)
    (worktree / "README.md").write_text("changed\n", encoding="utf-8")
    source.worktree_path = worktree
    source.branch_name = branch
    store.save(source)
    source = store.start_integration(source.id, "integration queued")
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate Source",
            prompt="Integrate",
            metadata={"source_task_id": source.id},
        )
    )
    store.finish_task(integration.id, TaskStatus.blocked, "integration repair started")

    class SuccessfulRunner:
        def __init__(self, configured: StewardConfig) -> None:
            self.config = configured

        def paths(self, task: TaskRecord, *, name: str = "worker") -> tuple[Path, Path]:
            path = self.config.transcripts_dir / task.id / name
            return path / "codex.jsonl", path / "last-message.md"

        def run(
            self,
            task: TaskRecord,
            _prompt: str,
            cwd: Path,
            *,
            name: str = "worker",
            **_kwargs: object,
        ) -> WorkerResult:
            cwd = Path(cwd)
            transcript_path, last_message_path = self.paths(task, name=name)
            transcript_path.parent.mkdir(parents=True, exist_ok=True)
            transcript_path.write_text("{}\n", encoding="utf-8")
            last_message_path.write_text("done\n", encoding="utf-8")
            return WorkerResult(
                completed=True,
                command=["fake"],
                cwd=cwd,
                exit_code=0,
                transcript_path=transcript_path,
                last_message_path=last_message_path,
                final_message="done",
            )

    executor = StewardExecutor(config, store, runner=SuccessfulRunner(config))
    failure: _PathPolicyStatusParseError | UnicodeDecodeError
    if failure_kind == "malformed":
        failure = _PathPolicyStatusParseError("?? " + ("x" * 300))
    else:
        failure = UnicodeDecodeError("utf-8", b"\\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(executor.worktrees, "reset_to_main", lambda _path: None)
    monkeypatch.setattr(executor.worktrees, "apply_patch", lambda _path, _patch: None)

    if policy == "forbidden":
        def fail_forbidden(_path: Path) -> list[str]:
            raise failure

        monkeypatch.setattr(executor.worktrees, "forbidden_paths", fail_forbidden)
    else:
        monkeypatch.setattr(executor.worktrees, "forbidden_paths", lambda _path: [])

        def fail_frozen(_path: Path, _task: TaskRecord) -> list[str]:
            raise failure

        monkeypatch.setattr(executor.worktrees, "frozen_paths", fail_frozen)

    transcript_messages: list[tuple[str, str]] = []

    class Transcript:
        def write(self, stage: str, message: str) -> None:
            transcript_messages.append((stage, message))

    if repair == "conflict":
        result = executor._repair_integration_conflict(
            source.id, "conflict", "rebased patch", integration.id, Transcript()
        )
    else:
        result = executor._repair_integration_validation_failure(
            source.id, [], "rebased patch", integration.id, Transcript()
        )

    assert result is False
    saved_source = store.get(source.id)
    saved_integration = store.get(integration.id)
    assert saved_source.status == TaskStatus.integrating
    assert saved_source.worktree_path == worktree
    assert worktree.exists()
    assert saved_integration.status == TaskStatus.blocked
    assert saved_integration.summary == PATH_POLICY_STATUS_PARSE_SUMMARY
    event = next(
        event
        for event in store.events(integration.id)
        if event.kind == "path_policy.blocked"
    )
    assert event.data["integration_task_id"] == integration.id
    if failure_kind == "malformed":
        assert event.data["diagnostic"] == failure.diagnostic
    else:
        assert "diagnostic" not in event.data
    assert ("path_policy_blocked", PATH_POLICY_STATUS_PARSE_SUMMARY) in transcript_messages
    assert not any(
        event.kind == "path_policy.blocked" for event in store.events(source.id)
    )
    revision_event = (
        "worker.integration_revision_finished"
        if repair == "conflict"
        else "worker.validation_revision_finished"
    )
    assert any(event.kind == revision_event for event in store.events(source.id))


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
            ),
        }
    )
    store = TaskStore.create(config.db_path)
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


def test_durable_push_persists_transport_retry_before_success(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    real_push = Worktrees.push_head_to_main
    real_command = run_command
    attempts = 0
    trace: list[str] = []

    def transient_push(worktrees, path):
        nonlocal attempts
        attempts += 1
        trace.append("push")
        if attempts == 1:
            raise RuntimeError("Could not resolve host: github.com")
        return real_push(worktrees, path)

    def command(argv, cwd, *, timeout=None, **_kwargs):
        if argv and argv[0] == "gh":
            trace.append(argv[2])
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", transient_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert _drive_durable(executor, integration.id)

    saved = store.get(integration.id)
    events = store.events(integration.id)
    assert saved.status == TaskStatus.pushed
    assert attempts == 2
    assert any(event.kind == "pipeline.push.retry" for event in events)
    assert any(event.kind == "pipeline.push" for event in events)
    assert trace == ["push", "push", "comment", "close"]
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))

def test_durable_push_blocks_after_bounded_transport_failures(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    attempts = 0

    def fail_push(_worktrees, _path):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Could not resolve host: github.com")

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("unsuccessful durable push must not invoke GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", fail_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert not _drive_durable(executor, integration.id)

    saved = store.get(integration.id)
    events = store.events(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "push made no progress"
    assert attempts == 2
    assert any(event.kind == "pipeline.push.failure" for event in events)
    assert any(event.kind == "pipeline.push.retry" for event in events)
    assert not any(event.kind == "pipeline.push" for event in events)
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))

def test_push_retry_classification_excludes_remote_rejection() -> None:
    assert _is_transient_push_failure("Could not resolve host: github.com")
    assert _is_transient_push_failure("unexpected status 503 Service Unavailable")
    assert not _is_transient_push_failure("remote rejected: permission denied")
    assert not _is_transient_push_failure("non-fast-forward update rejected")


def test_durable_push_rejection_does_not_update_feature_issue(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )

    def rejected_push(_worktrees, _path):
        raise RuntimeError("remote rejected: permission denied")

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("rejected durable push must not invoke GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", rejected_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert not _drive_durable(executor, integration.id)

    saved = store.get(integration.id)
    events = store.events(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "push failed: remote rejected: permission denied"
    assert any(event.kind == "pipeline.push.failure" for event in events)
    assert not any(event.kind == "pipeline.push.retry" for event in events)
    assert not any(event.kind == "pipeline.push" for event in events)
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))


def test_durable_integration_rebase_does_not_update_feature_issue(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    _advance_durable(executor, integration.id, 4)
    (config.repo_root / "REMOTE.md").write_text("remote change\n", encoding="utf-8")
    run_command(["git", "add", "REMOTE.md"], cwd=config.repo_root, check=True)
    run_command(["git", "commit", "-m", "remote change"], cwd=config.repo_root, check=True)
    run_command(["git", "push", "origin", "main"], cwd=config.repo_root, check=True)

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("integration rebase must not update GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    outcome = executor.advance_once(integration.id)

    assert outcome.status == "child_pipeline"
    child = store.list_pipelines(integration.id)[-1]
    assert child.trigger == "integration-rebase"
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))


def test_durable_push_closes_one_feature_issue_after_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    commands: list[list[str]] = []

    def fake_run_command(command, cwd, *, timeout=None, **_kwargs):
        commands.append(command)
        return CommandResult(command, cwd, 0, "", "")

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", fake_run_command)
    assert _drive_durable(executor, integration.id)

    comment = next(command for command in commands if command[:3] == ["gh", "issue", "comment"])
    close = next(command for command in commands if command[:3] == ["gh", "issue", "close"])
    assert comment[3] == "42"
    assert "Source task: " + source.id in comment[comment.index("--body") + 1]
    assert close[3] == "42"
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_closed: #42" in transcript.read_text(encoding="utf-8")

def test_durable_ambiguous_push_also_closes_feature_issue(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    real_push = Worktrees.push_head_to_main
    real_command = run_command
    commands: list[list[str]] = []

    def push_then_report_ambiguity(worktrees, path):
        result = real_push(worktrees, path)
        raise RuntimeError("connection lost after remote accepted the push")

    def command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            return CommandResult(command, cwd, 0, "", "")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", push_then_report_ambiguity)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    assert _drive_durable(executor, integration.id)

    events = store.events(integration.id)
    assert any(event.kind == "pipeline.push.ambiguous_resolved" for event in events)
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))
    assert [item[0:3] for item in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and transcript.is_file()


def test_reconciled_push_updates_feature_issue_before_sealing(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    _advance_durable(executor, integration.id, 7)
    real_push = Worktrees.push_head_to_main

    def push_then_crash(worktrees, path):
        result = real_push(worktrees, path)
        raise KeyboardInterrupt("daemon stopped after remote acceptance")

    monkeypatch.setattr(Worktrees, "push_head_to_main", push_then_crash)
    with pytest.raises(KeyboardInterrupt):
        executor.advance_once(integration.id)

    commands: list[list[str]] = []
    real_command = run_command

    def command(argv, cwd, *, timeout=None, **_kwargs):
        if argv and argv[0] == "gh":
            commands.append(argv)
            return CommandResult(argv, cwd, 0, "", "")
        return real_command(argv, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", command)
    daemon = StewardDaemon(config, store)
    task = store.get(integration.id)
    pipeline = store.list_pipelines(integration.id)[0]
    active = next(
        event
        for event in store.events(integration.id)
        if event.kind == "pipeline.phase.started"
        and event.data.get("phase") == "push"
    )
    outcome = daemon._reconcile_interrupted_push(
        task, pipeline, str(active.data["action_id"])
    )

    assert outcome.disposition.value == "ingested"
    assert store.get(integration.id).status == TaskStatus.pushed
    assert any(event.kind == "github.issue_closed" for event in store.events(source.id))
    assert [item[:3] for item in commands] == [
        ["gh", "issue", "comment"],
        ["gh", "issue", "close"],
    ]
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_closed: #42" in transcript.read_text(encoding="utf-8")
    assert executor.advance_once(integration.id).status == "ready_to_seal"


def test_durable_push_remains_pushed_when_feature_issue_update_fails(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )

    real_command = run_command

    def failed_command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            return CommandResult(command, cwd, 1, "", "api unavailable")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", failed_command)
    assert _drive_durable(executor, integration.id)

    assert store.get(integration.id).status == TaskStatus.pushed
    event = next(
        event for event in store.events(source.id) if event.kind == "github.issue_update_failed"
    )
    assert event.data["issue_number"] == 42
    assert event.data["step"] == "comment"
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_update_failed: #42 comment" in transcript.read_text(encoding="utf-8")

def test_durable_push_skips_multiple_feature_issues(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42, 43)
    )
    commands: list[list[str]] = []

    real_command = run_command

    def unexpected_command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            pytest.fail("multiple selected feature issues must not invoke GitHub")
        return real_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_command)
    assert _drive_durable(executor, integration.id)

    event = next(
        event for event in store.events(source.id) if event.kind == "github.issue_update_skipped"
    )
    assert event.data["issue_count"] == 2
    assert commands == []
    transcript = store.get(integration.id).transcript_path
    assert transcript is not None and "issue_update_skipped" in transcript.read_text(encoding="utf-8")

def test_durable_push_blocks_without_explicit_source_metadata(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    task = store.get(integration.id)
    task.spec.metadata.pop("source_task_id", None)
    store.save(task)
    pushes: list[object] = []

    def unexpected_push(_worktrees, _path):
        pushes.append(True)
        pytest.fail("missing integration source must not push")

    def unexpected_github(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            pytest.fail("missing integration source must not update GitHub")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    monkeypatch.setattr(Worktrees, "push_head_to_main", unexpected_push)
    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_github)
    assert not _drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "integration source task missing"
    assert pushes == []
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))

def test_durable_push_skips_terminal_integration_source(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, source, integration, executor = _durable_push_setup(
        config, tmp_path, monkeypatch, issue_numbers=(42,)
    )
    store.finish_task(source.id, TaskStatus.failed, "source failed before integration")
    commands: list[list[str]] = []

    def unexpected_command(command, cwd, *, timeout=None, **_kwargs):
        if command and command[0] == "gh":
            commands.append(command)
            pytest.fail("terminal integration source must not be mutated")
        return run_command(command, cwd, timeout=timeout, **_kwargs)

    def unexpected_push(_worktrees, _path):
        pytest.fail("terminal integration source must not be published")

    monkeypatch.setattr("coquic_steward.execution.executor.run_command", unexpected_command)
    monkeypatch.setattr(Worktrees, "push_head_to_main", unexpected_push)
    assert not _drive_durable(executor, integration.id)

    assert store.get(source.id).status == TaskStatus.failed
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "integration source already terminal: failed"
    assert not any(event.kind.startswith("github.issue_") for event in store.events(source.id))
    assert commands == []


def test_durable_commit_message_failure_blocks_before_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    original_run = executor.runner.run

    def invalid_commit_message(task, prompt, cwd, **kwargs):
        result = original_run(task, prompt, cwd, **kwargs)
        stage = kwargs.get("stage")
        if getattr(stage, "value", stage) == "commit_message":
            result.final_message = '{"subject":"not conventional","body":"Body"}'
        return result

    monkeypatch.setattr(executor.runner, "run", invalid_commit_message)
    assert not _drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "commit message generation failed"
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_durable_integration_phase_preserves_child_pipeline_boundaries(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    outcomes = _advance_durable(executor, integration.id, 4)
    assert outcomes[-1].next_phase.value == "integration"
    assert len(store.list_pipelines(integration.id)) == 1
    assert not any(event.kind == "integration.retry_requested" for event in store.events(integration.id))

def test_durable_integration_phase_uses_persisted_validation_boundary(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    outcomes = _advance_durable(executor, integration.id, 3)
    assert outcomes[-1].next_phase.value == "review"
    assert any(event.kind == "pipeline.validation.result" for event in store.events(integration.id))

def test_durable_integration_phase_records_accepted_tree_identity(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)
    _advance_durable(executor, integration.id, 4)
    pipeline = store.list_pipelines(integration.id)[0]
    assert pipeline.output_identity
    assert pipeline.patch_identity
    assert pipeline.phase == "integration"

def test_durable_integration_validation_failure_creates_repair_child(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)

    def failing_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "integration-failed.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("integration gate failed\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake"], cwd=cwd, passed=False, exit_code=1,
                output_path=output, summary="integration gate failed"
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", failing_gates)
    outcomes = _advance_durable(executor, integration.id, 3)
    assert outcomes[-1].status == "child_pipeline"
    assert store.list_pipelines(integration.id)[-1].trigger == "validation-repair"

def test_durable_commit_failure_blocks_without_push(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    config, store, _source, integration, executor = _durable_push_setup(config, tmp_path, monkeypatch)

    def fail_commit(_self, _path, _message, _body="", *, expected_tree=None):
        raise RuntimeError("commit hook failed")

    monkeypatch.setattr("coquic_steward.execution.worktree.Worktrees.commit_all", fail_commit)
    assert not _drive_durable(executor, integration.id)
    saved = store.get(integration.id)
    assert saved.status == TaskStatus.blocked
    assert any(event.kind == "pipeline.blocked" for event in store.events(integration.id))
    assert not any(event.kind == "pipeline.push" for event in store.events(integration.id))

def test_executor_drives_blocking_review_through_durable_repair(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "durable-review-repair-codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'case "$last" in\n'
        '  */reviewer-1/last-message.md) printf \'%s\\n\' \'{"verdict":"block","summary":"needs revision","findings":[{"severity":"high","title":"bad","file":"README.md","line":1,"detail":"bad text","recommendation":"fix it"}],"validation_gaps":[],"remaining_risk":""}\' > "$last" ;;\n'
        '  */formality-1/last-message.md) printf \'%s\\n\' \'{"dispositions":[{"sourceIndex":0,"disposition":"required","rationale":"bounded repair","followUp":null}]}\' > "$last" ;;\n'
        '  */reviewer-2/last-message.md) printf \'%s\\n\' \'{"verdict":"approve","summary":"repaired","findings":[],"validation_gaps":[],"remaining_risk":""}\' > "$last" ;;\n'
        '  */pipeline-2-implementation-1/last-message.md) printf \'repaired change\\n\' > README.md; printf \'done\\n\' > "$last" ;;\n'
        '  */commit-message-2/last-message.md) printf \'%s\\n\' \'{"subject":"fix: durable review repair","body":"persist the repaired tree"}\' > "$last" ;;\n'
        '  *) printf \'initial change\\n\' > README.md; printf \'done\\n\' > "$last" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id, finalize=True)

    iterations = store.iterations(task.id)
    assert [item.iteration for item in iterations] == [0, 1]
    assert all(item.patch_path is not None for item in iterations)
    assert store.get(task.id).status == TaskStatus.succeeded
    assert len(store.list_pipelines(task.id)) == 2
    assert any(event.kind == "pipeline.formality.effective" for event in store.events(task.id))
    assert any(event.kind == "pipeline.review.failure" for event in store.events(task.id))
    assert any(
        event.kind == "pipeline.child.created"
        and event.data.get("trigger") == "review-repair"
        for event in store.events(task.id)
    )
    assert sum(event.kind == "pipeline.review.raw" for event in store.events(task.id)) == 2

def test_executor_persists_durable_iteration_as_first_class_record(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path, change="initial change")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id)
    iterations = store.iterations(task.id)
    assert [item.iteration for item in iterations] == [0]
    assert iterations[0].patch_path is not None
    review = next(event for event in store.events(task.id) if event.kind == "pipeline.review.raw")
    assert review.data["review"]["verdict"] == "approve"
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))

def test_executor_routes_validation_failure_to_durable_child_pipeline(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path, change="bad")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def failing_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "validation-failed.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("validation failed\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-validation"],
                cwd=cwd,
                passed=False,
                exit_code=1,
                output_path=output,
                summary="validation failed",
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", failing_gates)
    executor = StewardExecutor(config, store)
    outcomes = _advance_durable(executor, task.id, 3)

    assert outcomes[-1].status == "child_pipeline"
    pipelines = store.list_pipelines(task.id)
    assert len(pipelines) == 2
    child = pipelines[-1]
    assert child.trigger == "validation-repair"
    assert child.metadata["packet"]["validation"]["validations"]
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))

def test_executor_blocks_unchanged_validation_revision(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path, change="bad")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )

    def failing_gates(configured, task_id, cwd, **_kwargs):
        output = configured.logs_dir / task_id / "validation-failed.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("same failure\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-validation"], cwd=cwd, passed=False, exit_code=1,
                output_path=output, summary="same failure"
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", failing_gates)
    executor = StewardExecutor(config, store)
    assert not _drive_durable(executor, task.id)
    saved = store.get(task.id)
    assert saved.status == TaskStatus.blocked
    assert saved.summary == "validation made no progress"
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))

def test_validation_failure_state_uses_complete_validation_log(
    config: StewardConfig, tmp_path: Path
) -> None:
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    fake = _durable_codex(tmp_path, change="formatted")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    gate_runs = 0

    def gates(configured, task_id, cwd, **_kwargs):
        nonlocal gate_runs
        gate_runs += 1
        output = configured.logs_dir / task_id / f"validation-{gate_runs}.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        if gate_runs == 1:
            (cwd / "README.md").write_text("gate repaired\n", encoding="utf-8")
        output.write_text("failed\n" if gate_runs == 1 else "ok\n", encoding="utf-8")
        return [
            ValidationResult(
                command=["fake-format"], cwd=cwd, passed=gate_runs > 1,
                exit_code=0 if gate_runs > 1 else 1, output_path=output,
                summary="ok" if gate_runs > 1 else "formatted files"
            )
        ]

    monkeypatch.setattr("coquic_steward.execution.executor.run_gates", gates)
    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id)
    assert gate_runs == 2
    assert any(event.kind == "pipeline.validation.failure" for event in store.events(task.id))

def test_executor_blocks_repeated_patch_and_validation_failure(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path, change="same patch")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates",
        lambda configured, task_id, cwd, **_kwargs: [
            ValidationResult(
                command=["fake-validation"], cwd=cwd, passed=False, exit_code=1,
                output_path=(configured.logs_dir / task_id / "failure.txt"),
                summary="same failure"
            )
        ],
    )
    output = config.logs_dir / task.id / "failure.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("same failure\n", encoding="utf-8")

    executor = StewardExecutor(config, store)
    assert not _drive_durable(executor, task.id)
    assert store.get(task.id).status == TaskStatus.blocked
    assert len(store.list_pipelines(task.id)) <= executor.MAX_PIPELINES
    assert any(event.kind == "pipeline.blocked" for event in store.events(task.id))

def test_executor_uses_durable_phase_order_for_validation_and_review(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = _durable_codex(tmp_path, change="review fixed")
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", _passing_durable_gates
    )

    executor = StewardExecutor(config, store)
    assert _drive_durable(executor, task.id)
    phases = [
        event.data["phase"]
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.started"
    ]
    assert phases[:6] == [
        "provisioned", "implementation", "validation", "review", "integration", "commit_message"
    ]
    assert any(event.kind == "pipeline.commit" for event in store.events(task.id))

def test_cli_enqueue_and_status(repo: Path, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    config = load_config()
    store = TaskStore.create(config.db_path)
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
    config = load_config()
    store = TaskStore.create(config.db_path)
    signal, _ = ingest_test_signal(
        store,
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
    config = load_config()
    store = TaskStore.create(config.db_path)
    store.engine.dispose()
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
    config = load_config()
    store = TaskStore.create(config.db_path)
    store.engine.dispose()

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
    config = load_config()
    store = TaskStore.create(config.db_path)
    store.engine.dispose()

    result = CliRunner().invoke(app, ["daemon", "--once", "--no-plan", "--no-dispatch"])

    assert result.exit_code == 1
    assert "remote push preflight failed" in result.output
    assert "TickResult" not in result.output


def test_cli_daemon_refuses_second_instance(
    config: StewardConfig, monkeypatch
) -> None:
    monkeypatch.chdir(config.repo_root)
    store = TaskStore.create(config.db_path)
    store.engine.dispose()

    with acquire_daemon_lock(config):
        result = CliRunner().invoke(
            app, ["daemon", "--once", "--no-plan", "--no-dispatch"]
        )

    assert result.exit_code == 1
    assert "Steward daemon already running" in result.output
    assert str(config.state_dir / "daemon.lock") in result.output


def test_store_records_in_progress_iteration_review(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
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
    store = TaskStore.create(config.db_path)
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

    reopened = TaskStore.open(config.db_path)
    saved = reopened.get(task.id)
    assert saved.spec.title == "CI"
    assert reopened.count_events("task.created") == 1


def test_store_persists_state_artifact_paths_relative(config: StewardConfig) -> None:
    from coquic_steward.core.models import ValidationResult

    store = TaskStore.create(config.db_path)
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
        assert row.transcript_path == f"steward/transcripts/{task.id}/worker/codex.jsonl"
        assert row.last_message_path == f"steward/transcripts/{task.id}/worker/last-message.md"
        assert row.patch_path == f"steward/patches/{task.id}/iteration-0.patch"
        assert json.loads(row.metadata_json) == {
            "note": "patches/looks-like-text",
            "source_patch_path": f"steward/patches/{task.id}/iteration-0.patch",
            "source_worktree_path": f"worktrees/{task.id}",
        }
        assert validation.output_path == f"steward/logs/{task.id}/iteration-0/validation.txt"
        assert validation.cwd == str(config.repo_root)
        assert iteration.worker_prompt_path == f"steward/prompts/{task.id}/worker.md"
        assert iteration.worker_transcript_path == f"steward/transcripts/{task.id}/worker/codex.jsonl"
        assert iteration.worker_last_message_path == f"steward/transcripts/{task.id}/worker/last-message.md"
        assert iteration.patch_path == f"steward/patches/{task.id}/iteration-0.patch"
        event = session.query(EventRow).filter_by(kind="artifact.ready").one()
        assert event.message == f"steward/patches/{task.id}/iteration-0.patch"
        assert json.loads(event.data_json) == {
            "failed": [{"output_path": f"steward/logs/{task.id}/iteration-0/validation.txt"}],
            "note": "patches/looks-like-text",
            "patch_path": f"steward/patches/{task.id}/iteration-0.patch",
        }

    reopened = TaskStore.open(config.db_path)
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
    store = TaskStore.create(config.db_path)
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
    assert TaskStore.open(config.db_path).get(task.id).worktree_path == external


def test_store_ignores_historic_relative_path_root(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    historic = config.state_dir / "logs" / task.id / "historic.txt"
    historic.parent.mkdir(parents=True, exist_ok=True)
    historic.write_text("historic\n", encoding="utf-8")
    relative = f"logs/{task.id}/historic.txt"
    current = config.db_path.parent / relative

    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.patch_path = relative
        row.metadata_json = json.dumps({"source_patch_path": relative})

    reopened = TaskStore.open(config.db_path)
    saved = reopened.get(task.id)
    assert saved.patch_path == current
    assert saved.patch_path != historic
    assert saved.spec.metadata["source_patch_path"] == str(current)


def test_store_open_preserves_existing_absolute_state_paths(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
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

    reopened = TaskStore.open(config.db_path)

    with Session(reopened.engine) as session:
        row = session.get(TaskRow, task.id)
        iteration = session.query(TaskIterationRow).filter_by(task_id=task.id).one()
        validation = session.query(ValidationRow).filter_by(task_id=task.id).one()
        event = session.query(EventRow).filter_by(task_id=task.id, kind="artifact.ready").one()
        assert row is not None
        assert row.patch_path == str(absolute_patch)
        assert json.loads(row.metadata_json) == {
            "source_patch_path": str(absolute_patch),
            "source_worktree_path": str(config.worktrees_dir / task.id),
        }
        assert iteration.worker_prompt_path == str(
            config.prompts_dir / task.id / "worker.md"
        )
        assert iteration.patch_path == str(absolute_patch)
        assert validation.cwd == str(config.worktrees_dir / task.id)
        assert validation.output_path == str(
            config.logs_dir / task.id / "validation.txt"
        )
        assert event.message == str(absolute_patch)
        assert json.loads(event.data_json) == {"patch_path": str(absolute_patch)}
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
    store = TaskStore.create(config.db_path)
    assert isinstance(store.control_loop_ledger, ControlLoopLedger)
    assert store.control_loop_ledger.epoch_id == config.ensure_epoch()["epochId"]


def test_archive_rejects_symlink_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "control-loop"
    root.symlink_to(target, target_is_directory=True)
    with pytest.raises((ValueError, RuntimeError)):
        ControlLoopArchive(root)

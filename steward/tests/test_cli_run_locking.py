from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app, run as run_cli_command
from coquic_steward.core.config import StewardConfig, load_config
from coquic_steward.core.lifecycle import ShutdownResult
from coquic_steward.core.models import DaemonLifecycleState
from coquic_steward.core.subprocesses import run_command
from coquic_steward.core.models import (
    TaskKind,
    TaskSpec,
    TaskStatus,
    TaskWorkflow,
    WorkerKind,
)
from coquic_steward.execution import StewardExecutor
from coquic_steward.orchestration import (
    DaemonAlreadyRunning,
    StewardDaemon,
    StewardPreflightError,
    acquire_daemon_lock,
)
from coquic_steward.storage import TaskStore


def _task_context(repo, monkeypatch):
    monkeypatch.chdir(repo)
    config = load_config()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="CLI locking test",
            prompt="run the test task",
        )
    )
    return config, store, task


def _invoke_run(repo, monkeypatch, task_id: str):
    monkeypatch.chdir(repo)
    return CliRunner().invoke(app, ["run", task_id])


def _assert_lock_held(config) -> None:
    with pytest.raises(DaemonAlreadyRunning):
        with acquire_daemon_lock(config):
            pass


def test_daemon_lock_inode_persists_after_release(repo, monkeypatch) -> None:
    config, _store, _task = _task_context(repo, monkeypatch)
    lock_path = config.state_dir / "daemon.lock"

    with acquire_daemon_lock(config):
        pass

    assert lock_path.is_file()


def test_run_rejects_daemon_lock_contention(repo, monkeypatch) -> None:
    config, _store, task = _task_context(repo, monkeypatch)

    class UnexpectedDaemon:
        def __init__(self, *_args, **_kwargs):
            pytest.fail("daemon must not start while another daemon owns the lock")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", UnexpectedDaemon)
    with acquire_daemon_lock(config):
        result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 1
    assert "Steward daemon already running:" in result.output
    assert str(config.state_dir / "daemon.lock") in result.output


def test_run_preserves_success_output_and_releases_lock(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)
    events: list[str] = []

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, *, session_supervisor=None):
            del session_supervisor
            events.append("construct")
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            events.append("reconcile")
            _assert_lock_held(config)

        def drive_selected_task(self, task_id: str) -> bool:
            events.append("drive")
            _assert_lock_held(config)
            assert task_id == task.id
            store.finish_task(task_id, TaskStatus.succeeded, "worker completed")
            return True

        def shutdown(self):
            events.append("shutdown")
            _assert_lock_held(config)
            return ShutdownResult()

        def tick(self, **_kwargs):
            pytest.fail("run must not invoke general daemon dispatch")

        def run_cycle(self, **_kwargs):
            pytest.fail("run must not invoke general daemon dispatch")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"ran {task.id} status=succeeded"
    events.append("released")
    assert events == ["construct", "reconcile", "drive", "shutdown", "released"]
    with acquire_daemon_lock(config):
        pass


def test_run_preserves_blocked_exit_and_output(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, *, session_supervisor=None):
            del session_supervisor
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            _assert_lock_held(config)

        def drive_selected_task(self, task_id: str) -> bool:
            _assert_lock_held(config)
            store.finish_task(task_id, TaskStatus.blocked, "worker blocked")
            return False

        def shutdown(self):
            _assert_lock_held(config)
            return ShutdownResult()

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"failed {task.id} status=blocked"
    with acquire_daemon_lock(config):
        pass


def test_run_nonblocked_failure_exits_nonzero_after_shutdown(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)
    events: list[str] = []

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, *, session_supervisor=None):
            del session_supervisor
            events.append("construct")
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            events.append("reconcile")
            _assert_lock_held(config)

        def drive_selected_task(self, task_id: str) -> bool:
            events.append("drive")
            _assert_lock_held(config)
            store.finish_task(task_id, TaskStatus.failed, "worker failed")
            return False

        def shutdown(self):
            events.append("shutdown")
            _assert_lock_held(config)
            return ShutdownResult()

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 1
    assert result.output.strip() == f"failed {task.id} status=failed"
    assert events == ["construct", "reconcile", "drive", "shutdown"]
    with acquire_daemon_lock(config):
        pass


@pytest.mark.parametrize("exception_type", [RuntimeError, KeyboardInterrupt])
def test_run_releases_lock_after_worker_exception(
    repo, monkeypatch, exception_type: type[BaseException]
) -> None:
    config, _store, task = _task_context(repo, monkeypatch)
    events: list[str] = []

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, *, session_supervisor=None):
            del session_supervisor
            events.append("construct")
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            events.append("reconcile")
            _assert_lock_held(config)

        def drive_selected_task(self, _task_id: str) -> bool:
            events.append("drive")
            _assert_lock_held(config)
            raise exception_type("worker stopped")

        def shutdown(self):
            events.append("shutdown")
            _assert_lock_held(config)
            return ShutdownResult()

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    with pytest.raises(exception_type, match="worker stopped"):
        run_cli_command(task.id)

    assert events == ["construct", "reconcile", "drive", "shutdown"]
    with acquire_daemon_lock(config):
        pass


def test_run_incomplete_shutdown_fails_without_completion_output(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, *, session_supervisor=None):
            del session_supervisor
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            _assert_lock_held(config)

        def drive_selected_task(self, task_id: str) -> bool:
            _assert_lock_held(config)
            store.finish_task(task_id, TaskStatus.succeeded, "worker completed")
            return True

        def shutdown(self):
            _assert_lock_held(config)
            return ShutdownResult(state=DaemonLifecycleState.stopping)

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 1
    assert "Steward daemon shutdown incomplete; owned containers may still be running." in result.output
    assert f"ran {task.id}" not in result.output
    with acquire_daemon_lock(config):
        pass


def test_run_advances_only_selected_task_without_planning_or_dispatch(
    repo, monkeypatch
) -> None:
    config, store, selected = _task_context(repo, monkeypatch)
    queued, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            workflow=TaskWorkflow.fix,
            worker=WorkerKind.custom,
            title="unrelated queued task",
            prompt="must not run",
        )
    )

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, *, session_supervisor=None):
            del session_supervisor
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            _assert_lock_held(config)

        def drive_selected_task(self, task_id: str) -> bool:
            _assert_lock_held(config)
            assert task_id == selected.id
            store.finish_task(task_id, TaskStatus.succeeded, "selected task completed")
            return True

        def tick(self, **_kwargs):
            pytest.fail("run must not invoke planning or general dispatch")

        def run_cycle(self, **_kwargs):
            pytest.fail("run must not invoke planning or general dispatch")

        def shutdown(self):
            _assert_lock_held(config)
            return ShutdownResult()

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    result = _invoke_run(repo, monkeypatch, selected.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"ran {selected.id} status=succeeded"
    assert store.get(queued.id).status == TaskStatus.queued
    with acquire_daemon_lock(config):
        pass

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
            "dry_run": False,
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
            "dry_run": False,
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
            "dry_run": False,
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
            "dry_run": True,
        }
    )
    config.ensure_dirs()

    def fail_run_command(*_args, **_kwargs):
        raise AssertionError("preflight should not run in dry-run mode")

    monkeypatch.setattr(
        "coquic_steward.orchestration.preflight.run_command", fail_run_command
    )

    StewardDaemon(config, TaskStore.create(config.db_path))

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
dry_run = false
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

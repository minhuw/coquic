from __future__ import annotations

import pytest
from typer.testing import CliRunner

from coquic_steward.cli import app, run as run_command
from coquic_steward.core.config import load_config
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
    acquire_daemon_lock,
)
from coquic_steward.storage import TaskStore


def _task_context(repo, monkeypatch):
    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        "coquic_steward.cli._configured_supervisor",
        lambda _config, _store: object(),
    )
    config = load_config()
    store = TaskStore(config.db_path)
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


def test_run_rejects_daemon_lock_contention(repo, monkeypatch) -> None:
    config, _store, task = _task_context(repo, monkeypatch)

    def fail_run(*_args, **_kwargs):
        pytest.fail("worker must not start while the daemon owns the lock")

    monkeypatch.setattr(StewardExecutor, "run_task", fail_run)
    with acquire_daemon_lock(config):
        result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 1
    assert "Steward daemon already running:" in result.output
    assert str(config.state_dir / "daemon.lock") in result.output


def test_run_preserves_success_output_and_releases_lock(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)

    def run_task(_executor, task_id: str) -> bool:
        _assert_lock_held(config)
        store.finish_task(task_id, TaskStatus.succeeded, "worker completed")
        return True

    monkeypatch.setattr(StewardExecutor, "run_task", run_task)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"ran {task.id} status=succeeded"
    with acquire_daemon_lock(config):
        pass


def test_run_preserves_blocked_exit_and_output(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)

    def run_task(_executor, task_id: str) -> bool:
        _assert_lock_held(config)
        store.finish_task(task_id, TaskStatus.blocked, "worker blocked")
        return False

    monkeypatch.setattr(StewardExecutor, "run_task", run_task)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"failed {task.id} status=blocked"
    with acquire_daemon_lock(config):
        pass


@pytest.mark.parametrize("exception_type", [RuntimeError, KeyboardInterrupt])
def test_run_releases_lock_after_worker_exception(
    repo, monkeypatch, exception_type: type[BaseException]
) -> None:
    config, _store, task = _task_context(repo, monkeypatch)

    def run_task(_executor, _task_id: str) -> bool:
        _assert_lock_held(config)
        raise exception_type("worker stopped")

    monkeypatch.setattr(StewardExecutor, "run_task", run_task)
    with pytest.raises(exception_type, match="worker stopped"):
        run_command(task.id)

    with acquire_daemon_lock(config):
        pass

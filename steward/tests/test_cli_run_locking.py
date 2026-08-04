from __future__ import annotations

from types import SimpleNamespace

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

    class FakeDaemon:
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
            return SimpleNamespace(state="stopped")

        def tick(self, **_kwargs):
            pytest.fail("run must not invoke general daemon dispatch")

        def run_cycle(self, **_kwargs):
            pytest.fail("run must not invoke general daemon dispatch")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    monkeypatch.setattr(
        StewardExecutor,
        "run_task",
        lambda *_args, **_kwargs: pytest.fail("legacy run_task must not be called"),
    )
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"ran {task.id} status=succeeded"
    events.append("released")
    assert events == ["construct", "reconcile", "drive", "shutdown", "released"]
    with acquire_daemon_lock(config):
        pass


def test_run_preserves_blocked_exit_and_output(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)

    class FakeDaemon:
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
            return SimpleNamespace(state="stopped")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    result = _invoke_run(repo, monkeypatch, task.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"failed {task.id} status=blocked"
    with acquire_daemon_lock(config):
        pass


def test_run_nonblocked_failure_exits_nonzero_after_shutdown(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)
    events: list[str] = []

    class FakeDaemon:
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
            return SimpleNamespace(state="stopped")

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

    class FakeDaemon:
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
            return SimpleNamespace(state="stopped")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    with pytest.raises(exception_type, match="worker stopped"):
        run_command(task.id)

    assert events == ["construct", "reconcile", "drive", "shutdown"]
    with acquire_daemon_lock(config):
        pass


def test_run_incomplete_shutdown_fails_without_completion_output(repo, monkeypatch) -> None:
    config, store, task = _task_context(repo, monkeypatch)

    class FakeDaemon:
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
            return SimpleNamespace(state="stopping")

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

    class FakeDaemon:
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
            return SimpleNamespace(state="stopped")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    monkeypatch.setattr(
        StewardExecutor,
        "run_task",
        lambda *_args, **_kwargs: pytest.fail("legacy run_task must not be called"),
    )
    result = _invoke_run(repo, monkeypatch, selected.id)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"ran {selected.id} status=succeeded"
    assert store.get(queued.id).status == TaskStatus.queued
    with acquire_daemon_lock(config):
        pass

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import coquic_steward.cli as cli_module
from coquic_steward.cli import app, daemon as daemon_cli_command, run as run_cli_command
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
from coquic_steward.execution.session import LocalSessionInvoker
from coquic_steward.orchestration import (
    DaemonAlreadyRunning,
    StewardDaemon,
    StewardPreflightError,
    TickResult,
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


def _invoke_cli_process(repo: Path, home: Path, *args: str):
    code = """
import sys
from typer.testing import CliRunner
from coquic_steward.cli import app
from coquic_steward.core.config import load_config
from coquic_steward.storage import TaskStore

result = CliRunner().invoke(app, sys.argv[1:])
print(result.output, end="")
if result.exit_code:
    raise SystemExit(result.exit_code)
state = TaskStore.open(load_config().db_path).get_daemon_state()
assert state is not None and state["lifecycle"] == "stopped", state
"""
    env = os.environ.copy()
    env["COQUIC_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _assert_lock_held(config) -> None:
    with pytest.raises(DaemonAlreadyRunning):
        with acquire_daemon_lock(config):
            pass


def test_cli_context_preserves_explicit_runtime_authority(repo, monkeypatch) -> None:
    monkeypatch.chdir(repo)
    monkeypatch.delenv("STEWARD_RELEASE_ID", raising=False)
    config_path = repo / "steward.toml"
    config_path.write_text(
        "[steward]\nlocal_codex_test_harness = false\n\n"
        "[steward.container]\nenabled = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("STEWARD_CONFIG_PATH", str(config_path))
    expected = load_config()
    TaskStore.create(expected.db_path).engine.dispose()

    store, config = cli_module._context()
    store.engine.dispose()

    assert config.container.enabled is False
    assert config.local_codex_test_harness is False


def test_standalone_planner_requires_explicit_runtime_boundary(tmp_path) -> None:
    local = StewardConfig(
        repo_root=tmp_path,
        local_codex_test_harness=True,
        task_image_digest=None,
    )
    assert isinstance(
        cli_module._configured_planner_session(local).invoker,
        LocalSessionInvoker,
    )

    productionless = StewardConfig(
        repo_root=tmp_path,
        local_codex_test_harness=False,
        task_image_digest=None,
    )
    with pytest.raises(ValueError, match="requires explicit"):
        cli_module._configured_planner_session(productionless)


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
    (config.coquic_home / "steward.toml").write_text(
        "[steward]\nlocal_codex_test_harness = true\n",
        encoding="utf-8",
    )
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
    (config.coquic_home / "steward.toml").write_text(
        "[steward]\nlocal_codex_test_harness = true\n",
        encoding="utf-8",
    )
    store = TaskStore.create(config.db_path)
    store.engine.dispose()

    result = CliRunner().invoke(app, ["daemon", "--once", "--no-plan", "--no-dispatch"])

    assert result.exit_code == 0
    assert "TickResult" in result.output


def test_cli_daemon_once_reopens_exact_store_in_new_process(
    repo: Path, coquic_home: Path, monkeypatch
) -> None:
    monkeypatch.chdir(repo)
    coquic_home.mkdir(parents=True, exist_ok=True)
    (coquic_home / "steward.toml").write_text(
        "[steward]\ndry_run = true\nlocal_codex_test_harness = true\n\n[steward.signals]\nenabled = []\n",
        encoding="utf-8",
    )
    config = load_config()
    store = TaskStore.create(config.db_path)
    store.engine.dispose()

    daemon = _invoke_cli_process(
        repo,
        coquic_home,
        "daemon",
        "--once",
        "--no-plan",
        "--no-dispatch",
    )
    assert daemon.returncode == 0, daemon.stderr
    assert "TickResult" in daemon.stdout

    status = _invoke_cli_process(repo, coquic_home, "status")
    assert status.returncode == 0, status.stderr

    audit = _invoke_cli_process(repo, coquic_home, "audit-invariants")
    assert audit.returncode == 0, audit.stderr
    assert audit.stdout.strip() == "ok"


def test_cli_daemon_once_skips_finalization_when_shutdown_incomplete(
    repo: Path, monkeypatch
) -> None:
    monkeypatch.chdir(repo)
    config = load_config()
    store = TaskStore.create(config.db_path)
    store.engine.dispose()
    events: list[str] = []
    finalizer_calls: list[object] = []

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, **_kwargs):
            events.append("construct")
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            events.append("reconcile")
            _assert_lock_held(config)

        def tick(self, **_kwargs):
            events.append("tick")
            _assert_lock_held(config)
            return TickResult()

        def shutdown(self):
            events.append("shutdown")
            _assert_lock_held(config)
            return ShutdownResult(state=DaemonLifecycleState.stopping)

    def fail_if_finalized(_store):
        finalizer_calls.append(_store)
        pytest.fail("incomplete shutdown must not finalize the Store")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    monkeypatch.setattr(TaskStore, "_finalize_exact_store", fail_if_finalized)
    result = CliRunner().invoke(
        app, ["daemon", "--once", "--no-plan", "--no-dispatch"]
    )

    assert result.exit_code == 1
    assert "Steward daemon shutdown incomplete; owned containers may still be running." in result.output
    assert "TickResult" not in result.output
    assert events == ["construct", "reconcile", "tick", "shutdown"]
    assert finalizer_calls == []
    with acquire_daemon_lock(config):
        pass


@pytest.mark.parametrize("failure_stage", ["startup", "tick"])
def test_cli_daemon_once_preserves_cycle_error_after_cleanup_failure(
    repo: Path, monkeypatch, failure_stage: str
) -> None:
    monkeypatch.chdir(repo)
    config = load_config()
    store = TaskStore.create(config.db_path)
    store.engine.dispose()
    events: list[str] = []

    class FakeDaemon(StewardDaemon):
        def __init__(self, _config, _store, **_kwargs):
            events.append("construct")
            _assert_lock_held(config)

        def startup_reconcile(self) -> None:
            events.append("startup")
            _assert_lock_held(config)
            if failure_stage == "startup":
                raise RuntimeError("startup failed")

        def tick(self, **_kwargs):
            events.append("tick")
            _assert_lock_held(config)
            if failure_stage == "tick":
                raise RuntimeError("tick failed")
            return TickResult()

        def shutdown(self):
            events.append("shutdown")
            _assert_lock_held(config)
            return ShutdownResult()

    def fail_finalize(_store):
        events.append("finalize")
        raise RuntimeError("finalization failed")

    monkeypatch.setattr("coquic_steward.cli.StewardDaemon", FakeDaemon)
    monkeypatch.setattr(TaskStore, "_finalize_exact_store", fail_finalize)

    with pytest.raises(RuntimeError, match=failure_stage):
        daemon_cli_command(
            once=True,
            no_plan=True,
            no_dispatch=True,
            max_dispatch=None,
        )

    expected_events = ["construct", "startup"]
    if failure_stage == "tick":
        expected_events.append("tick")
    expected_events.extend(["shutdown", "finalize"])
    assert events == expected_events
    with acquire_daemon_lock(config):
        pass


def test_cli_daemon_exits_when_push_preflight_fails(
    repo: Path, coquic_home: Path, monkeypatch
) -> None:
    monkeypatch.chdir(repo)
    coquic_home.mkdir(parents=True, exist_ok=True)
    (coquic_home / "steward.toml").write_text(
        """
[steward]
dry_run = false
local_codex_test_harness = true
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

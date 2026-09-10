"""Terminal private-home cleanup, including restart with no worktree/container."""

import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from coquic_steward.core.models import TaskKind, TaskSpec, TaskStatus, WorkerKind
from coquic_steward.execution.container import (
    ContainerBoundaryError, TaskContainerRuntime, _session_helper_main,
)
from coquic_steward.execution.session import SessionSupervisor, runtime_factory_for_config
from coquic_steward.storage import TaskStore


def delete_locally(monkeypatch, root, session_id, uid):
    monkeypatch.setattr("sys.argv", ["helper", "delete", str(root), json.dumps({
        "session_id": session_id, "session_uid": uid,
    })])
    _session_helper_main()


@pytest.mark.parametrize("linked_root", [False, True])
def test_delete_never_follows_root_or_descendant_symlinks(tmp_path, monkeypatch, linked_root):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    before = sentinel.stat()
    home = root / "session-one"
    if linked_root:
        home.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="ownership"):
            delete_locally(monkeypatch, root, home.name, os.geteuid())
        assert home.is_symlink()
    else:
        home.mkdir(mode=0o700)
        (home / "nested").mkdir()
        (home / "nested" / "link").symlink_to(outside, target_is_directory=True)
        (home / "file").write_bytes(b"private")
        delete_locally(monkeypatch, root, home.name, os.geteuid())
        delete_locally(monkeypatch, root, home.name, os.geteuid())
        assert not home.exists()
    assert sentinel.read_bytes() == b"untouched"
    assert sentinel.stat().st_mode == before.st_mode
    assert sentinel.stat().st_mtime_ns == before.st_mtime_ns


def test_delete_rejects_wrong_uid(tmp_path, monkeypatch):
    (tmp_path / "session-one").mkdir()
    with pytest.raises(ValueError, match="ownership"):
        delete_locally(monkeypatch, tmp_path, "session-one", os.geteuid() + 1)
    assert (tmp_path / "session-one").is_dir()


def retained_task(config):
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(TaskSpec(
        kind=TaskKind.custom, worker=WorkerKind.custom, title="cleanup", prompt="synthetic",
    ))
    task.worktree_path = config.worktrees_dir / task.id  # Already removed before restart.
    store.save(task)
    root = config.private_sessions_dir / task.id
    root.mkdir(mode=0o711)
    session = store.create_session(
        task.id, store.list_pipelines(task.id)[0].id,
        session_id="session-one", private_home_path=root / "session-one",
        private_home_relative_path=f"{task.id}/session-one",
    )
    (root / session.id / "sessions").mkdir(parents=True, mode=0o700)
    store.finish_task(task.id, TaskStatus.failed, "synthetic terminal task")
    store.add_event(task.id, "cleanup.container_removed", "already removed")
    store.add_event(task.id, "cleanup.worktree_removed", "already removed")
    return store, store.get(task.id), session, root


def test_restart_cleanup_does_not_provision_missing_paths(config, monkeypatch):
    config = replace(config, task_image_digest="sha256:" + "a" * 64)
    store, task, session, root = retained_task(config)
    calls = []

    def remove(runtime, *, session_id, session_uid):
        calls.append((session_id, session_uid))
        delete_locally(monkeypatch, runtime.config.private_sessions, session_id, os.geteuid())

    monkeypatch.setattr(TaskContainerRuntime, "remove_session_home", remove)
    monkeypatch.setattr(TaskContainerRuntime, "provision_task_paths", lambda _: pytest.fail("provisioned"))
    supervisor = SessionSupervisor(config, store, runtime_factory=lambda _: pytest.fail("normal factory"))
    supervisor.remove_session_homes(task.id)
    supervisor.remove_session_homes(task.id)
    assert calls == [(session.id, session.home_uid)]
    assert not root.exists()
    assert not task.worktree_path.exists()
    assert not (config.private_dir / "task-scratch" / task.id).exists()
    assert not (config.tasks_dir / task.id).exists()


@pytest.mark.parametrize("kind", ["unknown", "root-link", "nonterminal", "container-present"])
def test_cleanup_refuses_unproven_or_unknown_homes(config, monkeypatch, kind):
    config = replace(config, task_image_digest="sha256:" + "a" * 64)
    store, task, session, root = retained_task(config)
    outside = config.private_dir / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    if kind == "root-link":
        root.rename(root.with_name(root.name + "-retained"))
        root.symlink_to(outside, target_is_directory=True)
    elif kind == "unknown":
        (root / "unknown").symlink_to(outside, target_is_directory=True)
    elif kind == "nonterminal":
        task.status = TaskStatus.running
        monkeypatch.setattr(store, "get", lambda _: task)
    supervisor = SessionSupervisor(config, store, runtime_factory=lambda _: pytest.fail("normal factory"))
    if kind == "container-present":
        monkeypatch.setattr(supervisor, "_container_cleanup_proven", lambda _: False)
    monkeypatch.setattr(TaskContainerRuntime, "remove_session_home", lambda runtime, **kw:
                        delete_locally(monkeypatch, root, kw["session_id"], os.geteuid()))
    with pytest.raises((ValueError, OSError)):
        supervisor.remove_session_homes(task.id)
    assert sentinel.read_bytes() == b"untouched"


@pytest.mark.skipif(not os.environ.get("STEWARD_BOUNDARY_IMAGE"), reason="explicit digest-pinned Docker fixture required")
def test_real_docker_deletes_different_uid_0700_home_after_restart(config):
    assert os.geteuid() != 0
    assert "CapEff:\t0000000000000000" in Path("/proc/self/status").read_text()
    config = replace(config, task_image_digest=os.environ["STEWARD_BOUNDARY_IMAGE"])
    store, task, session, root = retained_task(config)
    runtime = runtime_factory_for_config(config, provision_paths=False)(task)
    home = root / session.id
    outside = config.private_dir / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    (home / "sessions" / "outside-link").symlink_to(outside, target_is_directory=True)
    runtime.provision_session(session_id=session.id, session_uid=session.home_uid)
    try:
        assert home.stat().st_uid == session.home_uid != os.geteuid()
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        with pytest.raises(PermissionError):
            list(home.iterdir())
        with pytest.raises(ContainerBoundaryError):
            runtime.remove_session_home(session_id=session.id, session_uid=session.home_uid + 1)
        linked_home = root / "session-linked"
        linked_home.symlink_to(outside, target_is_directory=True)
        try:
            with pytest.raises(ContainerBoundaryError):
                runtime.remove_session_home(session_id=linked_home.name, session_uid=session.home_uid)
            assert linked_home.is_symlink()
            assert sentinel.read_bytes() == b"untouched"
        finally:
            linked_home.unlink()
        supervisor = SessionSupervisor(config, store, runtime_factory=lambda _: pytest.fail("normal factory"))
        supervisor.remove_session_homes(task.id)
        supervisor.remove_session_homes(task.id)
        assert not root.exists()
        assert not task.worktree_path.exists()
        assert sentinel.read_bytes() == b"untouched"
        assert not list((root.parent / ".file-helper-cleanup").glob("*.json"))
    finally:
        if root.exists():
            runtime.remove_session_home(session_id=session.id, session_uid=session.home_uid)
            root.rmdir()


@pytest.mark.parametrize("local", [False, True])
def test_daemon_retries_home_cleanup_and_preserves_local_path(config, monkeypatch, local):
    from coquic_steward.orchestration.daemon import StewardDaemon

    config = replace(config, local_codex_test_harness=local,
                     task_image_digest="sha256:" + "a" * 64)
    store, task, session, root = retained_task(config)
    pipeline = store.list_pipelines(task.id)[0]
    store.add_event(task.id, "pipeline.ready_to_seal", "failed", {
        "pipeline_id": pipeline.id, "terminal_status": "failed",
    })
    calls = []

    def remove(runtime, *, session_id, session_uid):
        assert not local, "local harness used Docker cleanup"
        calls.append((session_id, session_uid))
        if len(calls) == 1:
            raise PermissionError("retryable synthetic deletion failure")
        delete_locally(monkeypatch, runtime.config.private_sessions, session_id, os.geteuid())

    monkeypatch.setattr(TaskContainerRuntime, "remove_session_home", remove)
    supervisor = SessionSupervisor(config, store, runtime_factory=lambda _: pytest.fail("normal factory"))
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    if not local:
        assert daemon.finalize_terminal_task(task.id) is False
        events = store.events(task.id)
        assert events[-1].kind == "cleanup_retryable"
        assert events[-1].data["step"] == "session-home-remove"
        assert not any(event.kind == "cleanup.session_homes_removed" for event in events)
        assert root.exists()
    assert daemon.finalize_terminal_task(task.id) is True
    assert not root.exists()
    assert not task.worktree_path.exists()
    assert store.events(task.id)[-1].kind == "cleanup_complete"
    assert calls == ([] if local else [(session.id, session.home_uid)] * 2)

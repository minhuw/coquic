"""Regression checks for daemon/worker ownership and hostile file handoffs."""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.agents.invocation import InvocationOutcome
from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
from coquic_steward.execution.container import (
    ContainerBoundaryError,
    PlannerContainerRuntime,
    SubprocessDockerClient,
    _handoff_directory,
    _provision_tree,
    _read_handoff,
    _write_handoff,
)
from coquic_steward.execution.container_config import PlannerContainerConfig, TaskRole
from coquic_steward.execution.session import (
    FreshPlannerSession,
    LocalSessionInvoker,
    SessionSupervisor,
    _copy_optional_file,
    ContainerSessionInvoker,
    build_fresh_planner_request,
    runtime_factory_for_config,
)
from coquic_steward.storage import TaskStore


@pytest.mark.parametrize("kind", ["symlink", "parent-link", "fifo", "directory", "hardlink", "oversized"])
def test_handoff_rejects_hostile_sources_without_reading_targets(tmp_path, kind):
    external = tmp_path / "external"
    external.mkdir()
    target = external / "message"
    target.write_bytes(b"harmless external target")
    before = target.stat()
    home = tmp_path / "home"
    home.mkdir()
    source = home / "message"
    if kind == "symlink":
        source.symlink_to(target)
    elif kind == "parent-link":
        (home / "nested").symlink_to(external, target_is_directory=True)
        source = home / "nested" / "message"
    elif kind == "fifo":
        os.mkfifo(source)
    elif kind == "directory":
        source.mkdir()
    elif kind == "hardlink":
        os.link(target, source)
    else:
        source.write_bytes(b"x" * 33)
    with pytest.raises((OSError, ValueError)):
        _read_handoff(source, max_bytes=32)
    assert target.stat().st_atime_ns == before.st_atime_ns
    assert target.read_bytes() == b"harmless external target"
    assert target.stat().st_mode == before.st_mode


@pytest.mark.parametrize("kind", ["symlink", "parent-link", "fifo", "directory", "hardlink"])
def test_atomic_handoff_never_writes_or_chmods_external_targets(tmp_path, kind):
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    target.chmod(0o640)
    before = target.stat()
    home = tmp_path / "home"
    home.mkdir()
    destination = home / "control"
    if kind == "symlink":
        destination.symlink_to(target)
    elif kind == "parent-link":
        (home / "nested").symlink_to(tmp_path, target_is_directory=True)
        destination = home / "nested" / "target"
    elif kind == "fifo":
        os.mkfifo(destination)
    elif kind == "directory":
        destination.mkdir()
    else:
        os.link(target, destination)
    with pytest.raises((OSError, ValueError)):
        _write_handoff(destination, b"not allowed")
    assert target.read_bytes() == b"untouched"
    assert target.stat().st_mode == before.st_mode
    assert target.stat().st_mtime_ns == before.st_mtime_ns


def test_private_schema_copy_is_bounded_and_atomic(tmp_path):
    source, destination = tmp_path / "schema", tmp_path / "private-schema"
    source.write_bytes(b"{}")
    assert _copy_optional_file(source, destination) == destination
    assert _read_handoff(destination) == b"{}"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert _read_handoff(tmp_path / "missing") is None
    assert not list(tmp_path.glob(".handoff-*"))
    with source.open("wb") as handle:
        handle.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="limit"):
        _copy_optional_file(source, destination)
    assert destination.read_bytes() == b"{}"


def test_group_provisioning_skips_symlinked_trees(tmp_path):
    root, outside = tmp_path / "tree", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    target = outside / "keep"
    target.write_bytes(b"unchanged")
    target.chmod(0o600)
    (root / "file-link").symlink_to(target)
    (root / "directory-link").symlink_to(outside, target_is_directory=True)
    (root / "regular").write_bytes(b"work")
    with _handoff_directory(root) as fd:
        _provision_tree(fd, os.geteuid(), os.getegid(), worktree=True)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755
    assert stat.S_IMODE((root / "regular").stat().st_mode) == 0o664


class HostileInvoker(LocalSessionInvoker):
    def __init__(self, target, *, interrupted=False, parent=False):
        super().__init__()
        self.target = target
        self.interrupted = interrupted
        self.parent = parent

    def invoke(self, request, *, append, **kwargs):
        append(b'{"type":"synthetic"}\n')
        destination = request.output_last_message
        if self.parent:
            old = destination.parent.with_name(destination.parent.name + "-moved")
            destination.parent.rename(old)
            destination.parent.symlink_to(self.target.parent, target_is_directory=True)
        elif self.interrupted:
            (destination.parent / "interruption.json").symlink_to(self.target)
        else:
            destination.symlink_to(self.target)
        return InvocationOutcome(
            exit_code=130 if self.interrupted else 0, stdout=b"", stderr=b"",
            incomplete_suffix=b"", events=(), provider_session_id=None,
            interrupted=self.interrupted,
        )


@pytest.mark.parametrize("interrupted,parent", [(False, False), (True, False), (False, True)])
def test_task_handoff_failure_is_durable_and_not_success(config, interrupted, parent):
    target = config.private_dir / "external-target"
    target.write_bytes(b"external sentinel")
    before = target.stat()
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(TaskSpec(
        kind=TaskKind.custom, worker=WorkerKind.custom, title="boundary", prompt="synthetic",
    ))
    supervisor = SessionSupervisor(
        config, store, invoker=HostileInvoker(target, interrupted=interrupted, parent=parent),
        image_digest="sha256:" + "a" * 64,
    )
    result = supervisor.start(
        task.id, store.list_pipelines(task.id)[0].id, role="implementation",
        prompt="synthetic", cwd=config.repo_root,
    )
    assert result.status.value == "failed"
    assert store.get_run(result.run_id).state == "failed"
    assert result.diagnostics["handoff_failed"]
    assert (result.transcript_path.parent / "handoff-error.json").is_file()
    assert not result.last_message_path.exists()
    assert not supervisor._active
    assert target.stat().st_atime_ns == before.st_atime_ns
    assert target.read_bytes() == b"external sentinel"
    assert target.stat().st_mode == before.st_mode


@pytest.mark.parametrize("parent", [False, True])
def test_planner_rejects_symlink_output_with_durable_evidence(config, parent):
    target = config.private_dir / "external-target"
    target.write_bytes(b"external sentinel")
    result = FreshPlannerSession(config, invoker=HostileInvoker(target, parent=parent)).run(
        "synthetic-planner", prompt="synthetic",
    )
    assert result.status.value == "failed"
    assert not result.last_message_path.exists()
    assert (result.transcript_path.parent / "handoff-error.json").is_file()
    assert target.read_bytes() == b"external sentinel"


def test_prepare_home_rejects_parent_symlinks(config):
    target = config.private_dir / "external"
    target.mkdir()
    link = config.private_sessions_dir / "hostile"
    link.symlink_to(target, target_is_directory=True)
    supervisor = SessionSupervisor(config, None, invoker=LocalSessionInvoker())
    with pytest.raises(OSError):
        supervisor._prepare_home(SimpleNamespace(private_home_path=link / "session"))
    assert list(target.iterdir()) == []


def test_planner_uid_hash_collision_does_not_share_private_identity(config, monkeypatch):
    monkeypatch.setattr(
        "coquic_steward.execution.session.hashlib.sha256",
        lambda _value: SimpleNamespace(hexdigest=lambda: "a" * 64),
    )
    first = build_fresh_planner_request(config, run_id="one", prompt="synthetic")
    second = build_fresh_planner_request(config, run_id="two", prompt="synthetic")
    assert first.request.session_uid != second.request.session_uid
    assert first.home.parent == second.home.parent


def test_helper_timeout_removes_only_its_exact_generated_container(config):
    class TimedOutDocker(SubprocessDockerClient):
        def __init__(self):
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append(argv)
            if argv[0] == "run":
                raise subprocess.TimeoutExpired(argv, 120)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    client = TimedOutDocker()
    runtime = PlannerContainerRuntime(PlannerContainerConfig(
        image="synthetic", image_digest="sha256:" + "a" * 64,
        history_root=config.repo_root, private_root=config.private_sessions_dir,
        output_root=config.private_dir,
    ), client=client)
    with pytest.raises(ContainerBoundaryError, match="timed out"):
        runtime.provision_session(session_id="session-one", session_uid=12345)
    name = client.calls[0][client.calls[0].index("--name") + 1]
    assert name.startswith("coquic-steward-files-")
    assert client.calls[1] == ["rm", "--force", name]
    argv = client.calls[0]
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--entrypoint") + 1] == "python"
    assert "sha256:" + "a" * 64 in argv
    assert argv.count("--mount") == 1
    assert "/var/run/docker.sock" not in " ".join(argv)


def test_planner_schema_rejection_has_daemon_owned_evidence(config):
    target = config.private_dir / "external-schema"
    target.write_bytes(b"{}")
    source = config.private_dir / "schema-link"
    source.symlink_to(target)
    with pytest.raises(OSError):
        FreshPlannerSession(config).run("malformed-schema", prompt="synthetic", output_schema=source)
    failures = list((config.private_dir / "planner-evidence").glob("*/handoff-error.json"))
    assert len(failures) == 1
    assert b"malformed-schema" in failures[0].read_bytes()


@pytest.mark.skipif(not os.environ.get("STEWARD_BOUNDARY_IMAGE"), reason="explicit digest-pinned Docker fixture required")
@pytest.mark.parametrize("planner", [False, True])
def test_real_docker_provisioning_from_nonroot_capability_free_daemon(config, planner):
    assert os.geteuid() != 0
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status
    image = os.environ["STEWARD_BOUNDARY_IMAGE"]
    config = replace(config, task_image_digest=image)
    outside = config.private_dir / "outside"
    outside.mkdir()
    target = outside / "target"
    target.write_bytes(b"external sentinel")
    target.chmod(0o600)
    (config.repo_root / "outside-link").symlink_to(outside, target_is_directory=True)
    if planner:
        request = build_fresh_planner_request(config, run_id="synthetic", prompt="synthetic")
        root = request.home.parent
        root.chmod(0o711)
        runtime = PlannerContainerRuntime(PlannerContainerConfig(
            image=config.task_image, image_digest=image,
            history_root=config.repo_root, private_root=root, output_root=outside,
        ))
        session_id, uid = request.session_id, request.request.session_uid
    else:
        runtime = runtime_factory_for_config(config)(SimpleNamespace(
            id="boundary-fixture", worktree_path=config.repo_root,
        ))
        root = runtime.config.private_sessions
        session_id, uid = "session-fixture", 23456
        (root / session_id / "sessions").mkdir(parents=True, mode=0o700)
        assert config.repo_root.stat().st_uid == os.geteuid()
        assert config.repo_root.stat().st_gid == runtime.config.task_write_gid
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    home = root / session_id
    _write_handoff(home / "output-schema.json", b"{}")
    runtime.provision_session(session_id=session_id, session_uid=uid)
    client = SubprocessDockerClient()

    def worker(script, *, selected_uid=uid, gid=uid, extra_mounts=()):
        return client.run([
            "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--user", f"{selected_uid}:{gid}",
            "--mount", f"type=bind,src={root},dst=/private", *extra_mounts,
            "--entrypoint", "python", image, "-B", "-c", script,
        ], timeout=30)

    try:
        code = f"from pathlib import Path; import os; p=Path('/private/{session_id}'); "
        own = worker(code + "assert (p/'output-schema.json').read_bytes()==b'{}'; "
                     "(p/'last-message.md').write_bytes(b'captured'); os.chmod(p/'last-message.md',0o600)")
        assert own.returncode == 0, own.stderr
        assert worker(code + "(p/'last-message.md').read_bytes()", selected_uid=uid + 1).returncode != 0
        assert runtime.read_session_file("last-message.md", session_id=session_id, session_uid=uid) == b"captured"
        runtime.write_session_file("interruption.json", b"{}", session_id=session_id, session_uid=uid)
        assert worker(code + "assert (p/'interruption.json').read_bytes()==b'{}'").returncode == 0
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        # Exercise the real idle container and task wrapper without Codex or a
        # credential: allocate no global planner name and clean up only this ID.
        create = runtime.create_argv()
        name_index = create.index("--name")
        del create[name_index:name_index + 2]
        created = client.run(create, timeout=30)
        assert created.returncode == 0, created.stderr
        container_id = created.stdout.decode().strip()
        try:
            started = client.run(["start", container_id], timeout=30)
            assert started.returncode == 0, started.stderr
            command = ["/bin/task-entrypoint.sh", "run", "python", "-c",
                       "import os; from pathlib import Path; p=Path(os.environ['HOME']); "
                       "assert (p/'output-schema.json').read_bytes()==b'{}'; "
                       "(p/'wrapper-output').write_bytes(b'wrapper captured')"]
            argv = runtime.exec_argv(
                TaskRole.planner if planner else TaskRole.implementation,
                session_id=session_id, session_uid=uid, command=command,
                env={"COQUIC_STEWARD_RUN_ID": "synthetic-wrapper"}, interactive=True,
            )
            argv[argv.index(runtime.config.container_name)] = container_id
            result = client.run(argv, input=b"\0\0\0\0", timeout=30)
            assert result.returncode == 0, result.stderr
            assert runtime.read_session_file("wrapper-output", session_id=session_id, session_uid=uid) == b"wrapper captured"
            identity = ContainerSessionInvoker(runtime)._identity(
                SimpleNamespace(run_id="synthetic-wrapper", session_id=session_id, session_uid=uid),
                SimpleNamespace(poll=lambda: 0),
            )
            assert identity.pid > 1
        finally:
            removed = client.run(["rm", "--force", container_id], timeout=30)
            assert removed.returncode == 0, removed.stderr
        if not planner:
            mounts = ("--mount", f"type=bind,src={config.repo_root},dst=/worktree",
                      "--mount", f"type=bind,src={runtime.config.scratch},dst=/scratch")
            created = worker("from pathlib import Path; (Path('/worktree')/'worker-file').write_text('worker'); "
                             "(Path('/scratch')/'scratch-file').write_text('scratch')",
                             gid=runtime.config.task_write_gid, extra_mounts=mounts)
            assert created.returncode == 0, created.stderr
            (config.repo_root / "worker-file").write_text("daemon still has write access")
            (runtime.config.scratch / "scratch-file").write_text("daemon still has write access")
            denied = worker("from pathlib import Path; (Path('/worktree')/'forbidden').write_text('no')", extra_mounts=mounts)
            assert denied.returncode != 0
            assert not (config.repo_root / "forbidden").exists()
        before = target.stat()
        malformed = worker(code + "(p/'bad-link').symlink_to('/outside/target'); "
                           "(p/'bad-parent').symlink_to('/outside', target_is_directory=True); "
                           "os.mkfifo(p/'bad-fifo'); (p/'bad-directory').mkdir(); "
                           "f=(p/'bad-large').open('wb'); f.truncate(16777217); f.close()",
                           extra_mounts=("--mount", f"type=bind,src={outside},dst=/outside,readonly"))
        assert malformed.returncode == 0, malformed.stderr
        for name in ("bad-link", "bad-parent/target", "bad-fifo", "bad-directory", "bad-large"):
            with pytest.raises(ContainerBoundaryError):
                runtime.read_session_file(name, session_id=session_id, session_uid=uid)
        for name in ("bad-link", "bad-parent/target", "bad-fifo", "bad-directory"):
            with pytest.raises(ContainerBoundaryError):
                runtime.write_session_file(name, b"do not write", session_id=session_id, session_uid=uid)
        assert target.stat().st_atime_ns == before.st_atime_ns
        assert target.read_bytes() == b"external sentinel"
        assert target.stat().st_mode == before.st_mode
        cleaned = worker(code + "(p/'bad-fifo').unlink()")
        assert cleaned.returncode == 0, cleaned.stderr
    finally:
        # Return only this disposable fixture to its original daemon owner.
        runtime._trusted_files(root, "tree", {"uid": os.geteuid(), "gid": os.getegid(), "worktree": False})


@pytest.mark.parametrize("failure", ["nonzero", "cancelled", "exception", "interrupt"])
@pytest.mark.parametrize("cleanup", ["removed", "absent", "nonzero", "timeout", "exception"])
def test_abnormal_helper_exit_cleans_exact_name_outside_cancelled_owner(config, failure, cleanup):
    from coquic_steward.core.subprocesses import ProcessGroupCancellationOwner, current_subprocess_owner, use_subprocess_owner
    from coquic_steward.execution.container import ContainerErrorCategory

    owner = ProcessGroupCancellationOwner("cancelled-helper")
    containers = {"foreign-container"}
    calls = []

    class Docker(SubprocessDockerClient):
        def run(self, argv, **kwargs):
            calls.append(argv)
            if argv[0] == "run":
                assert current_subprocess_owner() is owner
                containers.add(argv[argv.index("--name") + 1])
                owner.force_cancel()
                if failure == "exception":
                    raise OSError("CLI failure")
                if failure == "interrupt":
                    raise KeyboardInterrupt()
                return subprocess.CompletedProcess(argv, -9 if failure == "cancelled" else 1, b"", b"private content")
            assert current_subprocess_owner() is None
            assert kwargs == {"timeout": 10, "max_output_bytes": 4096}
            name = calls[0][calls[0].index("--name") + 1]
            assert argv == ["rm", "--force", name]
            assert name.startswith("coquic-steward-files-")
            assert len(name.removeprefix("coquic-steward-files-")) == 32
            if cleanup == "timeout":
                raise subprocess.TimeoutExpired(argv, 10)
            if cleanup == "exception":
                raise OSError("cleanup connection lost")
            if cleanup == "nonzero":
                return subprocess.CompletedProcess(argv, 1, b"", b"daemon plugin not found")
            containers.remove(name)
            return subprocess.CompletedProcess(argv, 1 if cleanup == "absent" else 0, b"", f"Error response from daemon: No such container: {name}\n".encode() if cleanup == "absent" else b"")

    runtime = PlannerContainerRuntime(PlannerContainerConfig(
        image="synthetic", image_digest="sha256:" + "a" * 64,
        history_root=config.repo_root, private_root=config.private_sessions_dir,
        output_root=config.private_dir,
    ), client=Docker())
    cleanup_failed = cleanup in {"nonzero", "timeout", "exception"}
    expected = ContainerBoundaryError if cleanup_failed or failure in {"nonzero", "cancelled"} else OSError if failure == "exception" else KeyboardInterrupt
    with use_subprocess_owner(owner):
        with pytest.raises(expected) as caught:
            runtime.provision_session(session_id="session-one", session_uid=12345)
        assert current_subprocess_owner() is owner
    assert len(calls) == 2
    if cleanup_failed:
        assert caught.value.category is ContainerErrorCategory.ambiguous
        assert "cleanup is unverified" in str(caught.value)
        assert len(containers) == 2
    else:
        assert containers == {"foreign-container"}
    assert "foreign-container" in containers
    assert "private content" not in str(caught.value)

from __future__ import annotations

import json
import io
import subprocess
from pathlib import Path

import pytest

from coquic_steward.execution import (
    ContainerErrorCategory,
    ExecIdentity,
    TaskContainerConfig,
    TaskContainerRuntime,
    TaskRole,
)
from coquic_steward.agents.invocation import InvocationRequest
from coquic_steward.core.models import CodexStage
from coquic_steward.execution.session import ContainerSessionInvoker


class FakeDocker:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], **_kwargs):
        self.calls.append(argv)
        if argv[0] == "create":
            return subprocess.CompletedProcess(argv, 0, b"container-id\n", b"")
        if argv[0] == "inspect":
            labels = {
                "coquic.steward.task": "task-1",
                "coquic.steward.image-digest": "sha256:" + "a" * 64,
                "coquic.steward.runtime": "task-container-v1",
            }
            payload = {
                "Id": "container-id",
                "State": {"Status": "running", "Running": True, "Pid": 41},
                "Config": {"Image": "sha256:" + "a" * 64, "Labels": labels},
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps([payload]).encode(), b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


@pytest.fixture
def container_config(tmp_path: Path) -> TaskContainerConfig:
    return TaskContainerConfig(
        task_id="task-1",
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        worktree=tmp_path / "worktree",
        archive=tmp_path / "archive",
        private_sessions=tmp_path / "sessions",
        git_dir=tmp_path / "git-linked",
        git_common_dir=tmp_path / "git-common",
        scratch=tmp_path / "scratch",
    )


def test_create_argv_is_locked_and_task_scoped(container_config: TaskContainerConfig) -> None:
    runtime = TaskContainerRuntime(container_config, client=FakeDocker())
    argv = runtime.create_argv()
    assert argv[0] == "create"
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--read-only" in argv
    assert all("docker.sock" not in value for value in argv)
    assert all("CODEX_API_KEY" not in value for value in argv)
    assert argv[-1] == container_config.image_digest
    assert "/usr/local/bin/task-entrypoint.sh" not in argv
    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]
    assert any("dst=/task/worktree,rw" in value for value in mounts)
    assert any("dst=/task/scratch,rw" in value for value in mounts)


def test_role_mounts_and_git_environment_are_kernel_boundary_inputs(
    container_config: TaskContainerConfig,
) -> None:
    runtime = TaskContainerRuntime(container_config, client=FakeDocker())
    read_only = runtime.exec_argv(
        TaskRole.reviewer,
        session_uid=10000,
        session_id="session-review",
        command=["git", "status"],
    )
    implementation = runtime.exec_argv(
        TaskRole.implementation,
        session_uid=10001,
        session_id="session-implementation",
        command=["git", "status"],
    )
    assert "/task/worktree-ro" in read_only
    assert "/task/worktree" in implementation
    assert "CODEX_HOME=/task/session/session-review" in read_only
    with pytest.raises(Exception):
        runtime.exec_argv(
            TaskRole.reviewer,
            session_uid=10000,
            session_id="session-review",
            command=["true"],
            env={"CODEX_API_KEY": "fake-only"},
        )


def test_inspect_rejects_identity_mismatch(container_config: TaskContainerConfig) -> None:
    fake = FakeDocker()
    runtime = TaskContainerRuntime(container_config, client=fake)
    inspection = runtime.adopt()
    assert inspection.running
    assert runtime.ensure_started() == "container-id"
    assert fake.calls[0][0] == "inspect"


def test_host_paths_translate_to_stable_task_mounts(
    container_config: TaskContainerConfig,
) -> None:
    assert container_config.container_path(
        container_config.worktree / "steward" / "schema.json",
        TaskRole.reviewer,
    ) == "/task/worktree-ro/steward/schema.json"
    assert container_config.container_path(
        container_config.worktree / "src" / "file.zig",
        TaskRole.implementation,
    ) == "/task/worktree/src/file.zig"
    assert container_config.container_path(
        container_config.private_sessions / "session-1" / "last.md",
        TaskRole.implementation,
    ) == "/task/session/session-1/last.md"
    with pytest.raises(ValueError):
        container_config.container_path(Path("/daemon/credentials"), TaskRole.planner)


def test_signal_targets_validated_in_container_pid(
    container_config: TaskContainerConfig,
) -> None:
    fake = FakeDocker()
    runtime = TaskContainerRuntime(container_config, client=fake)
    runtime.signal(
        ExecIdentity(container_config.container_name, "run-identity", 4321, 10000), 15
    )
    argv = fake.calls[-1]
    assert argv[-1] == "4321"
    assert "run-identity" not in argv[-1:]
    with pytest.raises(Exception):
        runtime.signal(
            ExecIdentity(container_config.container_name, "run-identity"), 15
        )


class _FakeStreamProcess:
    def __init__(self) -> None:
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(b'{"type":"completed"}\n')
        self.stderr = io.BytesIO()
        self.returncode = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def send_signal(self, sig):
        self.returncode = 128 + sig

    def kill(self):
        self.returncode = 137


def test_container_invocation_translates_all_runtime_paths(
    container_config: TaskContainerConfig,
) -> None:
    for path in (
        container_config.worktree,
        container_config.archive,
        container_config.private_sessions / "session-one",
        container_config.git_dir,
        container_config.git_common_dir,
        container_config.scratch,
    ):
        assert path is not None
        path.mkdir(parents=True, exist_ok=True)
    last_message = (
        container_config.private_sessions / "session-one" / "last-message.md"
    )
    schema = container_config.private_sessions / "session-one" / "schema.json"
    schema.write_text("{}", encoding="utf-8")
    (last_message.parent / "wrapper-run-one.pid").write_text(
        "4321\n", encoding="ascii"
    )

    class FakeRuntime:
        config = container_config

        def ensure_started(self):
            self.started = True

        def exec_stream(self, role, **kwargs):
            self.role = role
            self.kwargs = kwargs
            return _FakeStreamProcess()

    runtime = FakeRuntime()
    request = InvocationRequest(
        codex_bin="/daemon/host/codex",
        cwd=container_config.worktree,
        prompt="prompt",
        output_last_message=last_message,
        output_schema=schema,
        stage=CodexStage.review,
        role=TaskRole.reviewer.value,
        session_uid=10000,
        session_id="session-one",
        run_id="run-one",
    )
    identities = []
    outcome = ContainerSessionInvoker(runtime).invoke(
        request,
        api_key="fake-key",
        append=lambda _line: None,
        observe=lambda _event: None,
        on_started=identities.append,
        timeout_seconds=1,
        interrupt_grace_seconds=0.1,
    )
    rendered = " ".join(runtime.kwargs["command"])
    assert outcome.completed
    assert runtime.started
    assert "/daemon/host" not in rendered
    assert str(container_config.worktree) not in rendered
    assert "/task/worktree-ro" in rendered
    assert "/task/session/session-one/last-message.md" in rendered
    assert "/task/session/session-one/schema.json" in rendered
    assert runtime.kwargs["workdir"] == "/task/worktree-ro"
    assert identities == [
        ExecIdentity(container_config.container_name, "run-one", 4321, 10000)
    ]

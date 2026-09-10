from __future__ import annotations

import hashlib
import json
import io
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import coquic_steward.execution as execution
import coquic_steward.execution.session as session_module

from coquic_steward.execution import (
    ContainerBoundaryError,
    ContainerErrorCategory,
    ExecIdentity,
    SessionSupervisor,
    TaskContainerConfig,
    TaskContainerRuntime,
    TaskRole,
)
from coquic_steward.core.subprocesses import run_command
from coquic_steward.execution.container import PlannerContainerRuntime, SubprocessDockerClient
from coquic_steward.execution.container_config import PlannerContainerConfig
from coquic_steward.agents.invocation import InvocationRequest
from coquic_steward.core.config import StewardAuthenticationConfig, StewardConfig
from coquic_steward.core.models import CodexStage, TaskKind, TaskSpec, WorkerKind
from coquic_steward.execution.session import ContainerSessionInvoker
from coquic_steward.execution.executor import _SessionRunnerAdapter
from coquic_steward.storage import TaskStore


class FakeDocker(SubprocessDockerClient):
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: list[str],
        *,
        input: bytes | None = None,
        timeout: float | None = None,
        max_output_bytes: int | None = None,
    ):
        self.calls.append(argv)
        if argv[0] == "create" and "session-files-v1" in " ".join(argv):
            self.helper_argv = argv
            return subprocess.CompletedProcess(argv, 0, ("d" * 64).encode(), b"")
        if argv[:3] == ["container", "inspect", "--format"] and argv[-1] == "d" * 64:
            return subprocess.CompletedProcess(argv, 1, b"[]", ("Error response from daemon: No such container: " + "d" * 64).encode())
        if argv == ["start", "--attach", "--interactive", "d" * 64]:
            helper = self.helper_argv
            if helper[-3] == "read":
                options = json.loads(helper[-1])
                mount = helper[helper.index("--mount") + 1]
                root = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
                data = session_module._read_handoff(
                    root / options["session_id"] / options["name"],
                    max_bytes=options["max_bytes"],
                )
                return subprocess.CompletedProcess(argv, 0, b"0" if data is None else b"1" + data, b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
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


def test_execution_package_exports_current_types_without_aliases() -> None:
    canonical = {
        "ContainerBoundaryError": ContainerBoundaryError,
        "TaskContainerRuntime": TaskContainerRuntime,
        "TaskContainerConfig": TaskContainerConfig,
        "TaskRole": TaskRole,
        "SessionSupervisor": SessionSupervisor,
    }
    for name, expected in canonical.items():
        assert execution.__dict__[name] is expected
    assert set(canonical).issubset(execution.__all__)

    removed = {
        "ContainerError",
        "ContainerRuntime",
        "DockerBoundary",
        "Role",
        "ContainerConfig",
        "PlannerConfig",
        "SessionSupervisorError",
        "CodexSessionSupervisor",
        "SessionRuntime",
    }
    assert removed.isdisjoint(execution.__dict__)
    assert removed.isdisjoint(execution.__all__)


def test_host_capture_is_unlimited_by_default(tmp_path: Path) -> None:
    output = 256 * 1024
    result = run_command(
        [
            sys.executable,
            "-c",
            "import os, sys; os.write(1, b'o' * %d); os.write(2, b'e' * %d)"
            % (output, output),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert len(result.stdout.encode("utf-8")) == output
    assert len(result.stderr.encode("utf-8")) == output


def test_host_capture_drains_both_streams_with_an_opt_in_byte_cap(
    tmp_path: Path,
) -> None:
    cap = 1024
    output = 512 * 1024
    result = run_command(
        [
            sys.executable,
            "-c",
            "import os; os.write(1, b'o' * %d); os.write(2, b'e' * %d)"
            % (output, output),
        ],
        cwd=tmp_path,
        max_output_bytes=cap,
    )

    assert result.returncode == 0
    assert result.stdout == "o" * cap
    assert result.stderr == "e" * cap


def test_host_capture_preserves_input_and_timeout_reaping(tmp_path: Path) -> None:
    input_result = run_command(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        cwd=tmp_path,
        input_text="input delivered\n",
        max_output_bytes=64,
    )
    assert input_result.stdout == "input delivered\n"

    timeout_result = run_command(
        [
            sys.executable,
            "-c",
            "import sys, time; print('ready', flush=True); print('error', file=sys.stderr, flush=True); time.sleep(30)",
        ],
        cwd=tmp_path,
        timeout=0.1,
        max_output_bytes=3,
    )
    assert timeout_result.returncode == 124
    assert timeout_result.stdout == "rea"
    assert timeout_result.stderr.startswith("err")
    assert "command timed out after 0.1 seconds" in timeout_result.stderr


def test_docker_capture_is_unlimited_by_default_and_bounded_when_opted_in() -> None:
    output = 256 * 1024
    client = SubprocessDockerClient(sys.executable)
    argv = [
        "-c",
        "import os, sys; os.write(1, b'o' * %d); os.write(2, b'e' * %d)"
        % (output, output),
    ]

    unlimited = client.run(argv)
    bounded = client.run(argv, max_output_bytes=1024)

    assert unlimited.returncode == 0
    assert len(unlimited.stdout) == output
    assert len(unlimited.stderr) == output
    assert bounded.stdout == b"o" * 1024
    assert bounded.stderr == b"e" * 1024


def test_docker_capture_delivers_input_and_reaps_after_timeout() -> None:
    client = SubprocessDockerClient(sys.executable)
    delivered = client.run(
        ["-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        input=b"docker input\n",
        max_output_bytes=64,
    )
    assert delivered.stdout == b"docker input\n"

    with pytest.raises(subprocess.TimeoutExpired) as error:
        client.run(
            [
                "-c",
                "import sys, time; sys.stdout.write('ready'); sys.stdout.flush(); time.sleep(30)",
            ],
            timeout=0.1,
            max_output_bytes=3,
        )
    assert error.value.output == b"rea"
    assert error.value.stderr == b""


def test_docker_timeout_kills_descendants_holding_capture_pipes() -> None:
    client = SubprocessDockerClient(sys.executable)
    code = (
        "import os, signal, time; "
        "child = os.fork(); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN) if child == 0 else None; "
        "time.sleep(3.5) if child == 0 else time.sleep(30)"
    )

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        client.run(["-c", code], timeout=0.2)

    assert time.monotonic() - started < 3.0


def test_planner_container_mounts_only_sealed_history_and_private_io(
    tmp_path: Path,
) -> None:
    history = tmp_path / "control-loop" / "planner-runs"
    private = tmp_path / "private" / "planner"
    output = tmp_path / "private" / "planner-output"
    for path in (history, private, output):
        path.mkdir(parents=True)
    config = PlannerContainerConfig(
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        history_root=history,
        private_root=private,
        output_root=output,
    )
    argv = PlannerContainerRuntime(config, client=FakeDocker()).create_argv()
    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]

    assert config.container_name == "coquic-steward-planner"
    assert config.network == "bridge"
    assert argv[argv.index("--network") + 1] == "bridge"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in argv
    assert "--privileged" not in argv
    assert len(mounts) == 3
    assert any(value.endswith("dst=/planner/history,readonly") for value in mounts)
    assert any(value.endswith("dst=/planner/session") for value in mounts)
    assert any(value.endswith("dst=/planner/output") for value in mounts)
    assert set(mounts) == {
        f"type=bind,src={history},dst=/planner/history,readonly",
        f"type=bind,src={private},dst=/planner/session",
        f"type=bind,src={output},dst=/planner/output",
    }
    assert all("steward.sqlite" not in value and "docker.sock" not in value for value in argv)

    for forbidden_network in ("none", "host"):
        with pytest.raises(ValueError, match="locked provider-egress network"):
            replace(config, network=forbidden_network)


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
    assert any(value.endswith("dst=/task/worktree") for value in mounts)
    assert any(value.endswith("dst=/task/scratch") for value in mounts)
    assert any(value.endswith("dst=/task/worktree-ro,readonly") for value in mounts)


def test_create_persists_every_configured_label_for_restart_adoption(
    container_config: TaskContainerConfig,
) -> None:
    configured = replace(
        container_config,
        labels={"coquic.steward.codex": "codex-0.144.6"},
    )

    class LifecycleDocker(FakeDocker):
        def __init__(self) -> None:
            super().__init__()
            self.created = False
            self.labels: dict[str, str] = {}

        def run(
            self,
            argv: list[str],
            *,
            input: bytes | None = None,
            timeout: float | None = None,
            max_output_bytes: int | None = None,
        ):
            self.calls.append(argv)
            if argv[0] == "inspect" and not self.created:
                return subprocess.CompletedProcess(
                    argv, 1, b"", b"Error: No such container"
                )
            if argv[0] == "create":
                self.created = True
                self.labels = {
                    argv[index + 1].split("=", 1)[0]: argv[index + 1].split("=", 1)[1]
                    for index, value in enumerate(argv)
                    if value == "--label"
                }
                return subprocess.CompletedProcess(argv, 0, b"container-id\n", b"")
            if argv[0] == "inspect":
                payload = {
                    "Id": "container-id",
                    "State": {"Status": "running", "Running": True, "Pid": 41},
                    "Config": {"Image": configured.image_digest, "Labels": self.labels},
                }
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps([payload]).encode(), b""
                )
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    fake = LifecycleDocker()
    TaskContainerRuntime(configured, client=fake).ensure_started()
    adopted = TaskContainerRuntime(configured, client=fake).ensure_started()
    assert adopted == "container-id"
    assert fake.labels == configured.labels


def test_commit_message_stage_reaches_wrapper_without_worktree_group(
    config: StewardConfig,
    container_config: TaskContainerConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    last_message = config.private_dir / "commit-message.md"
    last_message.write_text('{"subject":"test","body":""}\n', encoding="utf-8")

    class RecordingSupervisor:
        def start(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            return SimpleNamespace(
                status=SimpleNamespace(value="succeeded"),
                exit_code=0,
                transcript_path=config.private_dir / "commit-message.jsonl",
                last_message_path=last_message,
                provider_session_id=None,
                session_id="commit-message-session",
                run_id="commit-message-run",
                pipeline_id=store.list_pipelines(task.id)[0].id,
                diagnostics={},
            )

    supervisor = RecordingSupervisor()
    _SessionRunnerAdapter(config, store, supervisor).run(
        task,
        "write a commit message",
        config.repo_root,
        stage=CodexStage.commit_message,
        sandbox="read-only",
    )
    assert supervisor.kwargs["role"] is TaskRole.commit_message
    assert supervisor.kwargs["sandbox"] == "read-only"

    argv = TaskContainerRuntime(container_config, client=FakeDocker()).exec_argv(
        supervisor.kwargs["role"],
        session_uid=10000,
        session_id="commit-message-session",
        command=["true"],
    )
    assert str(container_config.task_write_gid) not in argv
    assert "--group-add" not in argv
    assert "10000:10000" in argv
    assert "/task/worktree-ro" in argv


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
    assert "10000:10000" in read_only
    assert f"10001:{container_config.task_write_gid}" in implementation
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


class _TrackedStreamProcess(_FakeStreamProcess):
    def __init__(self, *, stdin=None, returncode=None) -> None:
        self.stdin = stdin if stdin is not None else io.BytesIO()
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.returncode = returncode
        self.terminate_calls = 0
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1
        self.returncode = 143


class _UnreapableStreamProcess(_TrackedStreamProcess):
    def poll(self):
        return None

    def terminate(self):
        self.terminate_calls += 1
        raise OSError("terminate failed")

    def wait(self, timeout=None):
        self.wait_calls += 1
        return None


class _FailingStdin:
    def __init__(self, failure: str) -> None:
        self.failure = failure
        self.data = bytearray()

    def write(self, value: bytes) -> int:
        self.data.extend(value)
        if self.failure == "write":
            raise OSError("write failed")
        return len(value)

    def flush(self) -> None:
        if self.failure == "flush":
            raise OSError("flush failed")


def _invocation_request(container_config: TaskContainerConfig) -> InvocationRequest:
    for path in (
        container_config.worktree,
        container_config.archive,
        container_config.private_sessions / "session-one",
        container_config.git_dir,
        container_config.git_common_dir,
        container_config.scratch,
    ):
        path.mkdir(parents=True, exist_ok=True)
    last_message = (
        container_config.private_sessions / "session-one" / "last-message.md"
    )
    schema = container_config.private_sessions / "session-one" / "schema.json"
    schema.write_text("{}", encoding="utf-8")
    (last_message.parent / "wrapper-run-one.pid").write_text(
        "4321\n", encoding="ascii"
    )
    return InvocationRequest(
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


class _FailureRuntime(TaskContainerRuntime):
    def __init__(self, config: TaskContainerConfig, process: _TrackedStreamProcess):
        super().__init__(config, client=FakeDocker())
        self.process = process
        self.container_live = True
        self.signals: list[tuple[ExecIdentity, int]] = []
        self.stop_calls = 0

    def ensure_started(self):
        return None

    def exec_stream(
        self,
        role,
        *,
        session_uid,
        session_id,
        command,
        env=None,
        workdir=None,
    ):
        return self.process

    def signal(self, identity, sig):
        self.signals.append((identity, int(sig)))
        self.container_live = False
        self.process.returncode = 128 + int(sig)

    def stop(self, container_id=None, *, timeout=None):
        self.stop_calls += 1
        self.container_live = False
        self.process.returncode = 137

    def exec_is_live(self, identity):
        return self.container_live


class _StopFailureRuntime(_FailureRuntime):
    def stop(self, container_id=None, *, timeout=None):
        self.stop_calls += 1
        raise RuntimeError("task container stop failed")


class _StaleLivenessRuntime(_FailureRuntime):
    def signal(self, identity, sig):
        self.signals.append((identity, int(sig)))

    def stop(self, container_id=None, *, timeout=None):
        self.stop_calls += 1
        self.container_live = False

    def exec_is_live(self, identity):
        return True


class _ProbeFailureRuntime(_StaleLivenessRuntime):
    def __init__(self, config: TaskContainerConfig, process: _TrackedStreamProcess):
        super().__init__(config, process)
        self.probe_calls = 0

    def exec_is_live(self, identity):
        self.probe_calls += 1
        if self.probe_calls >= 3:
            raise RuntimeError("liveness probe failed")
        return True


def test_container_invocation_reaps_unidentified_exec_and_stops_container(
    container_config: TaskContainerConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _invocation_request(container_config)
    (request.output_last_message.parent / "wrapper-run-one.pid").unlink()
    process = _TrackedStreamProcess()
    runtime = _FailureRuntime(container_config, process)
    clock = iter((0.0, 3.0))
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(clock))

    with pytest.raises(RuntimeError, match="process identity"):
        ContainerSessionInvoker(runtime).invoke(
            request,
            api_key="secret-key",
            append=lambda _line: None,
            timeout_seconds=1,
            interrupt_grace_seconds=0.1,
        )

    assert process.stdin.getvalue() == b""
    assert process.terminate_calls == 1
    assert process.wait_calls == 1
    assert runtime.stop_calls == 1


def test_unidentified_cleanup_attempts_container_stop_when_raw_reap_fails(
    container_config: TaskContainerConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _invocation_request(container_config)
    (request.output_last_message.parent / "wrapper-run-one.pid").unlink()
    process = _UnreapableStreamProcess()
    runtime = _FailureRuntime(container_config, process)
    clock = iter((0.0, 3.0))
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(clock))

    with pytest.raises(
        RuntimeError, match="trusted wrapper did not publish a valid process identity"
    ) as failure:
        ContainerSessionInvoker(runtime).invoke(
            request,
            api_key="secret-key",
            append=lambda _line: None,
            timeout_seconds=1,
            interrupt_grace_seconds=0.1,
        )

    assert failure.value.__cause__ is None
    assert process.stdin.getvalue() == b""
    assert process.terminate_calls == 1
    assert process.wait_calls == 1
    assert runtime.stop_calls == 1
    assert not runtime.container_live


def test_container_invocation_reaps_exec_that_exits_before_identity(
    container_config: TaskContainerConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _invocation_request(container_config)
    (request.output_last_message.parent / "wrapper-run-one.pid").unlink()
    process = _TrackedStreamProcess(returncode=0)
    runtime = _FailureRuntime(container_config, process)
    clock = iter((0.0, 0.0))
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(clock))

    with pytest.raises(RuntimeError, match="process identity"):
        ContainerSessionInvoker(runtime).invoke(
            request,
            api_key="secret-key",
            append=lambda _line: None,
            timeout_seconds=1,
            interrupt_grace_seconds=0.1,
        )

    assert process.stdin.getvalue() == b""
    assert process.terminate_calls == 0
    assert process.wait_calls == 1
    assert runtime.stop_calls == 1


@pytest.mark.parametrize("failure", ["write", "flush"])
def test_container_invocation_reaps_identified_exec_on_key_setup_failure(
    container_config: TaskContainerConfig, failure: str
) -> None:
    request = _invocation_request(container_config)
    process = _TrackedStreamProcess(stdin=_FailingStdin(failure))
    runtime = _FailureRuntime(container_config, process)
    invoker = ContainerSessionInvoker(runtime)

    with pytest.raises(OSError, match=failure):
        invoker.invoke(
            request,
            api_key="secret-key",
            append=lambda _line: None,
            timeout_seconds=1,
            interrupt_grace_seconds=0.1,
        )

    assert process.wait_calls == 1
    assert runtime.signals == [
        (ExecIdentity(container_config.container_name, "run-one", 4321, 10000), 15)
    ]
    assert runtime.stop_calls == 0
    assert invoker.process is None
    assert invoker.identity is None


def test_container_invocation_reaps_identified_exec_when_on_started_fails(
    container_config: TaskContainerConfig,
) -> None:
    request = _invocation_request(container_config)
    process = _TrackedStreamProcess()
    runtime = _FailureRuntime(container_config, process)
    invoker = ContainerSessionInvoker(runtime)

    with pytest.raises(ValueError, match="callback failed"):
        invoker.invoke(
            request,
            api_key="secret-key",
            append=lambda _line: None,
            on_started=lambda _identity: (_ for _ in ()).throw(
                ValueError("callback failed")
            ),
            timeout_seconds=1,
            interrupt_grace_seconds=0.1,
        )

    assert process.wait_calls == 1
    assert runtime.signals
    assert runtime.stop_calls == 0
    assert invoker.process is None
    assert invoker.identity is None


def test_cleanup_signals_validated_pid_after_docker_client_exits(
    container_config: TaskContainerConfig,
) -> None:
    process = _TrackedStreamProcess(returncode=0)
    runtime = _FailureRuntime(container_config, process)
    invoker = ContainerSessionInvoker(runtime)
    identity = ExecIdentity(container_config.container_name, "run-one", 4321, 10000)

    assert invoker._cleanup_launch_failure(process, identity)
    assert runtime.signals == [(identity, 15)]
    assert not runtime.container_live


@pytest.mark.parametrize("runtime_type", [_StaleLivenessRuntime, _ProbeFailureRuntime])
def test_cleanup_falls_back_to_container_for_unconfirmed_identity_liveness(
    container_config: TaskContainerConfig,
    runtime_type: type[_FailureRuntime],
) -> None:
    process = _TrackedStreamProcess(returncode=0)
    runtime = runtime_type(container_config, process)
    invoker = ContainerSessionInvoker(runtime)
    identity = ExecIdentity(container_config.container_name, "run-one", 4321, 10000)

    assert invoker._cleanup_launch_failure(process, identity)
    assert runtime.signals == [
        (identity, 15),
        (identity, 9),
    ]
    assert runtime.stop_calls == 1
    assert process.wait_calls == 1


def test_cleanup_reports_unconfirmed_boundary_when_container_stop_fails(
    container_config: TaskContainerConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _invocation_request(container_config)
    (request.output_last_message.parent / "wrapper-run-one.pid").unlink()
    process = _TrackedStreamProcess()
    runtime = _StopFailureRuntime(container_config, process)
    clock = iter((0.0, 3.0))
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(clock))

    with pytest.raises(
        RuntimeError, match="trusted wrapper did not publish a valid process identity"
    ) as failure:
        ContainerSessionInvoker(runtime).invoke(
            request,
            api_key="secret-key",
            append=lambda _line: None,
            timeout_seconds=1,
            interrupt_grace_seconds=0.1,
        )

    assert failure.value.__cause__ is None
    assert failure.value.__notes__ == ["container exec cleanup unconfirmed"]
    assert process.returncode == 143
    assert not runtime.signals
    assert runtime.container_live


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

    class FakeRuntime(TaskContainerRuntime):
        def __init__(self) -> None:
            super().__init__(container_config, client=FakeDocker())

        def ensure_started(self):
            self.started = True

        def exec_stream(
            self,
            role,
            *,
            session_uid,
            session_id,
            command,
            env=None,
            workdir=None,
        ):
            self.role = role
            self.kwargs = {
                "session_uid": session_uid,
                "session_id": session_id,
                "command": command,
                "env": env,
                "workdir": workdir,
            }
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


@pytest.mark.parametrize("role,stage", [
    (TaskRole.planner, CodexStage.signal_planner),
    (TaskRole.implementation, CodexStage.code),
    (TaskRole.reviewer, CodexStage.review),
])
@pytest.mark.parametrize("resume", [None, "exact-provider-session"])
@pytest.mark.parametrize("key", [b"synthetic-wrapper-key", "synthetic-wrapper-é".encode()])
def test_real_wrapper_receives_inline_key_only_through_stdin(
    config, container_config, tmp_path, role, stage, resume, key,
):
    """Run the production shell wrapper with fake Codex, never Docker/provider I/O."""
    proxy = "http://127.0.0.1:12345/v1"
    config = replace(config, authentication=StewardAuthenticationConfig(
        proxy_url=proxy, api_key=key.decode(),
    ))
    request = replace(
        _invocation_request(container_config), role=role.value, stage=stage,
        proxy_url=config.authentication.proxy_url, provider_session_id=resume,
    )
    home = request.output_last_message.parent
    (home / "wrapper-run-one.pid").unlink()
    fake = tmp_path / "codex"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import hashlib, os, pathlib, sys\n"
        f"assert hashlib.sha256(os.environ['CODEX_API_KEY'].encode()).hexdigest() == {hashlib.sha256(key).hexdigest()!r}\n"
        "assert 'OPENAI_API_KEY' not in os.environ\n"
        "assert not (pathlib.Path(os.environ['CODEX_HOME']) / 'auth.json').exists()\n"
        "assert sys.stdin.buffer.read() == b'prompt\\n'\n"
        "print('{\"type\":\"completed\"}')\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    wrapper = Path(__file__).resolve().parents[1] / "containers" / "task-entrypoint.sh"

    class FramedInput:
        def __init__(self, pipe):
            self.pipe = pipe
            self.prefix = b""

        def write(self, value):
            # Identity must have been accepted before credential delivery.
            assert invoker.identity is not None
            assert invoker.identity.pid > 1
            self.prefix += value
            return self.pipe.write(value)

        def __getattr__(self, name):
            return getattr(self.pipe, name)

    class WrapperRuntime(TaskContainerRuntime):
        def ensure_started(self):
            return None

        def exec_stream(self, selected_role, **kwargs):
            self.argv = self.exec_argv(selected_role, interactive=True, **kwargs)
            self.launch_env = {
                "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
                "HOME": str(home), "CODEX_HOME": str(home), "LANG": "C.UTF-8",
                **kwargs["env"],
            }
            process = subprocess.Popen(
                ["bash", str(wrapper), *kwargs["command"][1:]],
                env=self.launch_env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.framed_input = FramedInput(process.stdin)
            process.stdin = self.framed_input
            return process

    runtime = WrapperRuntime(container_config, client=FakeDocker())
    invoker = ContainerSessionInvoker(runtime)
    records = []
    outcome = invoker.invoke(
        request, api_key=config.read_codex_api_key_bytes(), append=records.append,
        timeout_seconds=5, interrupt_grace_seconds=0.1,
    )
    assert outcome.completed, outcome.stderr
    assert records == [b'{"type":"completed"}\n']
    assert runtime.framed_input.prefix == len(key).to_bytes(4, "big") + key
    assert key.decode() not in repr(runtime.argv)
    assert key.decode() not in repr(runtime.launch_env)
    assert "CODEX_API_KEY" not in runtime.launch_env
    docker_env = [runtime.argv[i + 1] for i, arg in enumerate(runtime.argv[:-1]) if arg == "--env"]
    assert not any(value.startswith(("CODEX_API_KEY=", "OPENAI_API_KEY=")) for value in docker_env)
    mapped = request.argv(
        codex_bin="codex", path_mapper=lambda path: container_config.container_path(path, role),
    )
    wrapper_index = runtime.argv.index("/bin/task-entrypoint.sh")
    assert runtime.argv[wrapper_index:] == ["/bin/task-entrypoint.sh", "run", *mapped]
    assert [value for value in mapped if value.startswith("model_provider")] == [
        'model_provider="steward"',
        'model_providers.steward.name="Steward proxy"',
        f'model_providers.steward.base_url="{proxy}"',
        'model_providers.steward.wire_api="responses"',
        'model_providers.steward.env_key="CODEX_API_KEY"',
        'model_providers.steward.requires_openai_auth=false',
    ]
    assert key not in outcome.stderr + b"".join(records)
    assert not list(home.rglob("auth.json"))
    assert not list(home.rglob("config.toml"))
    assert all(key not in path.read_bytes() for path in home.rglob("*") if path.is_file())

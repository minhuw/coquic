from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import coquic_steward.cli as cli_module
from coquic_steward.core.config import (
    StewardConfig,
    StewardDeploymentConfig,
    StewardLimits,
)
from coquic_steward.core.lifecycle import DockerResourceManager
from coquic_steward.core.subprocesses import CommandResult, run_command
from coquic_steward.execution.container import (
    ContainerBoundaryError,
    ContainerErrorCategory,
    ContainerInspection,
    ExecIdentity,
    ExecResult,
    SubprocessDockerClient,
    TaskContainerRuntime,
    ValidationContainerRuntime,
    bind_deployment_identity,
    deployment_runtime_factory,
)
from coquic_steward.execution.container_config import (
    ContainerLimits,
    TaskContainerConfig,
)
from coquic_steward.execution.container_config import ValidationContainerConfig
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.session import (
    SessionSupervisor,
    session_supervisor_for_config,
)
from coquic_steward.execution.validation import (
    MAX_VALIDATION_OUTPUT_BYTES,
    _docker_validation_runner,
    default_gates,
    run_validation,
)
from coquic_steward.core.models import OwnedDockerUsage, TaskKind, TaskSpec, WorkerKind
from coquic_steward.storage import TaskStore


def _deployment(tmp_path: Path, **overrides) -> StewardDeploymentConfig:
    values = {
        "enabled": True,
        "home": tmp_path,
        "repository": tmp_path / "repository",
        "host_uid": 1000,
        "host_gid": 1000,
        "docker_gid": 999,
        "codex_credential_path": tmp_path / "codex",
        "github_token_path": tmp_path / "github-token",
        "git_ssh_key_path": tmp_path / "git-ssh-key",
        "git_known_hosts_path": tmp_path / "known_hosts",
        "min_free_bytes": 1000,
        "max_owned_docker_bytes": 2000,
        "recovery_free_bytes": 1500,
        "recovery_owned_docker_bytes": 1000,
    }
    values.update(overrides)
    return StewardDeploymentConfig(**values)


def test_deployment_requires_hysteresis(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="recovery_free_bytes"):
        _deployment(tmp_path, recovery_free_bytes=1000)


def test_validation_container_is_no_network_and_separate_from_task_image(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    output = tmp_path / "output"
    store = tmp_path / "store"
    for path in (worktree, output, store):
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="validation-run",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=worktree,
        output=output,
        store=store,
    )
    argv = ValidationContainerRuntime(config).create_argv()
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--restart") + 1] == "no"
    assert "--read-only" in argv
    assert "/tmp:rw,noexec,nosuid,nodev,size=8589934592,mode=1777" in argv
    assert "/validation/worktree" in " ".join(argv)
    assert "/var/run/docker.sock" not in " ".join(argv)


def _validation_inspection(config: ValidationContainerConfig) -> dict[str, object]:
    return {
        "Id": "d" * 64,
        "Name": f"/{config.container_name}",
        "Image": config.image_digest,
        "State": {"Status": "running", "Running": True, "Pid": 41},
        "Config": {
            "Image": config.image_digest,
            "User": f"{config.uid}:{config.gid}",
            "Labels": config.labels,
            "Entrypoint": ["/bootstrap/sh"],
            "Cmd": ["/bootstrap/validation-entrypoint.sh", "--idle"],
            "WorkingDir": "/validation/worktree",
            "Env": [
                "NIX_REGISTRATION=/validation/closure-info/registration",
                "NIX_MATERIALIZED_STORE_PATHS=/validation/closure-info/materialized-store-paths",
                "NIX_STORE_PATHS=/validation/closure-info/store-paths",
                "PYTHONPATH=/nix/store/source/opt/coquic/steward/src",
                "ZIG_GLOBAL_CACHE_DIR=/tmp/zig-global-cache",
                "ZIG_LOCAL_CACHE_DIR=/tmp/zig-local-cache",
                *(f"{key}={value}" for key, value in config.environment),
            ],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "Privileged": False,
            "ReadonlyRootfs": True,
            "Init": True,
            "Memory": config.limits.memory_bytes,
            "PidsLimit": config.limits.pids,
            "RestartPolicy": {"Name": "no"},
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "LogConfig": {
                "Type": "local",
                "Config": {
                    "max-file": str(config.limits.log_max_files),
                    "max-size": f"{config.limits.log_max_bytes}b",
                },
            },
            "Tmpfs": dict(config.tmpfs),
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(mount.source),
                "Destination": mount.target,
                "RW": not mount.read_only,
            }
            for mount in config.mounts
        ],
    }


def test_validation_policy_is_shared(tmp_path: Path) -> None:
    worktree, output, store, git_common = (
        tmp_path / name for name in ("worktree", "output", "store", "git-common")
    )
    for path in (worktree, output, store, git_common):
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="shared-policy",
        image="coquic-steward-validation",
        image_digest="sha256:" + "d" * 64,
        worktree=worktree,
        output=output,
        store=store,
        git_common_dir=git_common,
        limits=ContainerLimits(
            memory_bytes=3 * 1024**3,
            pids=321,
            scratch_bytes=5 * 1024**3,
            log_max_bytes=7 * 1024**2,
            log_max_files=4,
        ),
        uid=12000,
        gid=12001,
    )
    runtime = ValidationContainerRuntime(config)
    create_argv = runtime.create_argv()
    run_argv = runtime.run_argv(["git", "status"])

    for option in ("--mount", "--env", "--tmpfs"):
        create_values = {
            create_argv[index + 1]
            for index, value in enumerate(create_argv[:-1])
            if value == option
        }
        run_values = {
            run_argv[index + 1]
            for index, value in enumerate(run_argv[:-1])
            if value == option
        }
        assert create_values == run_values
    for option, expected in (
        ("--network", "none"),
        ("--user", "12000:12001"),
        ("--pids-limit", "321"),
        ("--memory", str(3 * 1024**3)),
    ):
        assert create_argv[create_argv.index(option) + 1] == expected
        assert run_argv[run_argv.index(option) + 1] == expected
    assert run_argv[-3:] == ["--exec", "git", "status"]

    payload = _validation_inspection(config)
    runtime._validate_inspection(
        ContainerInspection(
            container_id="d" * 64,
            name=config.container_name,
            state="running",
            running=True,
            labels=config.labels,
            image=config.image_digest,
            raw=payload,
        )
    )
    payload["Config"]["Env"].append("UNEXPECTED=1")
    with pytest.raises(ContainerBoundaryError) as error:
        runtime._validate_inspection(
            ContainerInspection(
                container_id="d" * 64,
                name=config.container_name,
                state="running",
                running=True,
                labels=config.labels,
                image=config.image_digest,
                raw=payload,
            )
        )
    assert error.value.category is ContainerErrorCategory.identity_mismatch


def test_validation_container_refuses_same_name_foreign_image(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="collision",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )
    payload = _validation_inspection(config)
    payload["Image"] = "sha256:" + "f" * 64

    class ForeignDocker(SubprocessDockerClient):
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
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )

    docker = ForeignDocker()
    runtime = ValidationContainerRuntime(config, client=docker)

    with pytest.raises(ContainerBoundaryError) as error:
        runtime.ensure_started()

    assert error.value.category is ContainerErrorCategory.identity_mismatch
    assert [call[0] for call in docker.calls] == ["inspect"]


def test_validation_container_refuses_same_image_with_foreign_runtime(
    tmp_path: Path,
) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="collision-runtime",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )
    payload = _validation_inspection(config)
    payload["HostConfig"]["Memory"] = config.limits.memory_bytes // 2

    class ForeignDocker(SubprocessDockerClient):
        def run(
            self,
            argv: list[str],
            *,
            input: bytes | None = None,
            timeout: float | None = None,
            max_output_bytes: int | None = None,
        ):
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )

    runtime = ValidationContainerRuntime(config, client=ForeignDocker())

    with pytest.raises(ContainerBoundaryError) as error:
        runtime.ensure_started()

    assert error.value.category is ContainerErrorCategory.identity_mismatch


def test_validation_exec_returns_the_canonical_gate_exit_code(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="nonzero-gate",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )

    class NonzeroGateDocker(SubprocessDockerClient):
        def run(
            self,
            argv: list[str],
            *,
            input: bytes | None = None,
            timeout: float | None = None,
            max_output_bytes: int | None = None,
        ):
            return subprocess.CompletedProcess(argv, 23, b"gate output", b"gate failed")

    result = ValidationContainerRuntime(
        config, client=NonzeroGateDocker()
    ).exec(["false"])

    assert result.exit_code == 23
    assert result.stdout == b"gate output"
    assert result.stderr == b"gate failed"


def test_validation_container_waits_for_entrypoint_readiness(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("worktree", "output", "store")]
    for path in paths:
        path.mkdir()
    config = ValidationContainerConfig(
        run_id="startup-readiness",
        image="coquic-steward-validation",
        image_digest="sha256:" + "c" * 64,
        worktree=paths[0],
        output=paths[1],
        store=paths[2],
    )

    class RecordingDocker(SubprocessDockerClient):
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
            if argv[0] == "inspect":
                return subprocess.CompletedProcess(argv, 1, b"", b"No such container")
            if argv[0] == "create":
                return subprocess.CompletedProcess(argv, 0, ("d" * 64).encode(), b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    docker = RecordingDocker()

    assert ValidationContainerRuntime(config, client=docker).ensure_started() == "d" * 64
    assert [call[0] for call in docker.calls] == ["inspect", "create", "start", "exec"]
    assert docker.calls[-1][-3:] == [
        "/bootstrap/sh",
        "-c",
        "test -f /tmp/coquic-validation-ready",
    ]


_VALIDATION_TRUNCATION_MARKER = (
    "[output truncated by Steward validation boundary]"
)


def _assert_bounded_validation_artifact(
    result, *, expected_exit_code: int
) -> None:
    artifact = result.output_path.read_text(encoding="utf-8")
    stdout = artifact.split("STDOUT:\n", 1)[1].split("\n\nSTDERR:\n", 1)[0]
    stderr = artifact.split("STDERR:\n", 1)[1].rstrip("\n")

    assert result.exit_code == expected_exit_code
    assert not result.passed
    assert artifact.count(_VALIDATION_TRUNCATION_MARKER) == 2
    assert len(stdout.encode("utf-8")) <= MAX_VALIDATION_OUTPUT_BYTES
    assert len(stderr.encode("utf-8")) <= MAX_VALIDATION_OUTPUT_BYTES
    assert result.summary == stdout.strip()[-1000:]


def _validation_task_context(config: StewardConfig):
    store = TaskStore.create(config.db_path)
    task, _created = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="bounded validation",
            prompt="validate",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    task.worktree_path = config.repo_root
    store.save(task)
    return store, task, pipeline


def test_run_validation_bounds_host_dual_stream_artifact(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    oversized_stdout = "stdout:" + "o" * (MAX_VALIDATION_OUTPUT_BYTES + 128)
    oversized_stderr = "stderr:" + "e" * (MAX_VALIDATION_OUTPUT_BYTES + 128)
    calls: list[dict[str, object]] = []

    def recording_run_command(
        command, cwd, *, timeout=None, max_output_bytes=None, **kwargs
    ):
        calls.append(
            {
                "command": command,
                "timeout": timeout,
                "max_output_bytes": max_output_bytes,
                "kwargs": kwargs,
            }
        )
        if command[:2] == ["git", "rev-parse"]:
            return CommandResult(command, cwd, 0, "", "")
        return CommandResult(
            command,
            cwd,
            17,
            oversized_stdout,
            oversized_stderr,
        )

    monkeypatch.setattr(
        "coquic_steward.execution.validation.run_command", recording_run_command
    )
    result = run_validation(
        config,
        "host-bounded",
        config.repo_root,
        "validation.txt",
        ["verbose-gate"],
    )

    assert calls[-1]["max_output_bytes"] == MAX_VALIDATION_OUTPUT_BYTES
    _assert_bounded_validation_artifact(result, expected_exit_code=17)


def test_direct_validation_runner_uses_bootstrap_and_writable_nix_boundary(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "sha256:" + "c" * 64
    config = replace(
        config,
        validation_image="coquic-steward-validation",
        validation_image_digest=digest,
    )
    argv_calls: list[tuple[list[str], dict[str, object]]] = []

    class RecordingDockerClient(SubprocessDockerClient):
        def __init__(self, _docker_bin):
            pass

        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            argv_calls.append(
                (
                    argv,
                    {
                        "input": input,
                        "timeout": timeout,
                        "max_output_bytes": max_output_bytes,
                    },
                )
            )
            return subprocess.CompletedProcess(
                argv, 17, b"", b"canonical gate failed"
            )

    monkeypatch.setattr(
        "coquic_steward.execution.validation.SubprocessDockerClient",
        RecordingDockerClient,
    )

    monkeypatch.setattr(
        "coquic_steward.execution.validation._validation_git_common_dir",
        lambda _worktree: config.repo_root / ".git",
    )
    runner = _docker_validation_runner(config, "integration-task", config.repo_root)
    result = runner(["nix", "flake", "check"], config.repo_root, 30)

    assert result.returncode == 17
    argv, kwargs = argv_calls[0]
    assert kwargs["max_output_bytes"] == MAX_VALIDATION_OUTPUT_BYTES
    assert "--read-only" in argv
    assert any("dst=/nix/var/nix" in value for value in argv)
    assert any(value.startswith("/nix/store:rw,") for value in argv)
    assert argv[argv.index(digest) + 1 :] == ["--exec", "nix", "flake", "check"]


def test_direct_validation_runner_bounds_dual_stream_output_and_timeout(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "sha256:" + "c" * 64
    config = replace(
        config,
        validation_image="coquic-steward-validation",
        validation_image_digest=digest,
    )
    clients = []

    class RecordingDockerClient(SubprocessDockerClient):
        def __init__(self, _docker_bin):
            self.calls: list[dict[str, object]] = []
            clients.append(self)

        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            self.calls.append(
                {
                    "argv": argv,
                    "input": input,
                    "timeout": timeout,
                    "max_output_bytes": max_output_bytes,
                }
            )
            limit = max_output_bytes
            return subprocess.CompletedProcess(
                argv,
                23,
                b"stdout:" + b"o" * (limit + 128),
                b"stderr:" + b"e" * (limit + 128),
            )

    monkeypatch.setattr(
        "coquic_steward.execution.validation.SubprocessDockerClient",
        RecordingDockerClient,
    )
    monkeypatch.setattr(
        "coquic_steward.execution.validation._validation_git_common_dir",
        lambda _worktree: config.repo_root / ".git",
    )
    runner = _docker_validation_runner(config, "direct-bounded", config.repo_root)
    result = run_validation(
        config,
        "direct-bounded",
        config.repo_root,
        "validation.txt",
        ["verbose-gate"],
        command_runner=runner,
    )

    assert len(clients) == 1
    assert clients[0].calls[-1]["max_output_bytes"] == MAX_VALIDATION_OUTPUT_BYTES
    _assert_bounded_validation_artifact(result, expected_exit_code=23)

    class TimeoutDockerClient(SubprocessDockerClient):
        def __init__(self, _docker_bin):
            pass

        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr(
        "coquic_steward.execution.validation.SubprocessDockerClient",
        TimeoutDockerClient,
    )
    timeout_runner = _docker_validation_runner(
        config, "direct-timeout", config.repo_root
    )
    timeout_result = timeout_runner(["slow-gate"], config.repo_root, 30)
    assert timeout_result.returncode == 124
    assert timeout_result.stderr == "validation container timed out"


def test_task_container_validation_runner_propagates_cap_and_statuses(
    config: StewardConfig,
) -> None:
    store, task, pipeline = _validation_task_context(config)
    roots = {
        name: config.private_dir / f"task-validation-{name}"
        for name in ("archive", "sessions", "git", "common", "scratch")
    }
    for root in roots.values():
        root.mkdir(parents=True)
    task_config = TaskContainerConfig(
        task_id=task.id,
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        worktree=config.repo_root,
        archive=roots["archive"],
        private_sessions=roots["sessions"],
        git_dir=roots["git"],
        git_common_dir=roots["common"],
        scratch=roots["scratch"],
    )

    class RecordingClient(SubprocessDockerClient):
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            self.calls.append(
                {
                    "argv": argv,
                    "input": input,
                    "timeout": timeout,
                    "max_output_bytes": max_output_bytes,
                }
            )
            return subprocess.CompletedProcess(
                argv,
                0,
                b"stdout:" + b"o" * (MAX_VALIDATION_OUTPUT_BYTES + 128),
                b"stderr:" + b"e" * (MAX_VALIDATION_OUTPUT_BYTES + 128),
            )

    class RecordingRuntime(TaskContainerRuntime):
        def __init__(self) -> None:
            super().__init__(task_config, client=RecordingClient())
            self.exit_code = 17

        def ensure_started(self) -> str:
            return self.config.container_name

        def exec(
            self,
            role,
            *,
            session_uid,
            session_id,
            command,
            env=None,
            workdir=None,
            timeout=None,
        ) -> ExecResult:
            captured = self.client.run(command, timeout=timeout)
            return ExecResult(
                ExecIdentity(self.config.container_name, "validation-exec", 4321, session_uid),
                self.exit_code,
                captured.stdout,
                captured.stderr,
            )

    runtime = RecordingRuntime()
    executor = StewardExecutor(
        config, store, session_supervisor=SessionSupervisor(config, store, runtime=runtime)
    )
    runner = executor._container_validation_runner(task, pipeline)
    for exit_code in (17, 124):
        runtime.exit_code = exit_code
        result = run_validation(
            config,
            "task-bounded",
            config.repo_root,
            f"validation-{exit_code}.txt",
            ["verbose-gate"],
            command_runner=runner,
        )
        _assert_bounded_validation_artifact(result, expected_exit_code=exit_code)

    assert runtime.client.calls[-1]["max_output_bytes"] == MAX_VALIDATION_OUTPUT_BYTES


def test_isolated_validation_runner_propagates_cap_and_statuses(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, task, pipeline = _validation_task_context(config)
    store.claim_daemon_instance("isolated-validation-daemon")
    digest = "sha256:" + "b" * 64
    runtimes = []

    class RecordingRuntime(ValidationContainerRuntime):
        def __init__(self, runtime_config, *, docker_bin="docker") -> None:
            super().__init__(runtime_config, client=RecordingClient(), docker_bin=docker_bin)
            self.exit_code = 23
            self.cleaned = False
            runtimes.append(self)

        def ensure_started(self) -> str:
            return self.config.container_name

        def exec(self, command, *, workdir="/validation/worktree", timeout=None):
            captured = self.client.run(command, timeout=timeout)
            return ExecResult(
                ExecIdentity(self.config.container_name, "validation-exec", 4321, self.config.uid),
                self.exit_code,
                captured.stdout,
                captured.stderr,
            )

        def cleanup_owned(self, *, timeout=5) -> None:
            self.cleaned = True

    class RecordingClient(SubprocessDockerClient):
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            self.calls.append(
                {
                    "argv": argv,
                    "input": input,
                    "timeout": timeout,
                    "max_output_bytes": max_output_bytes,
                }
            )
            return subprocess.CompletedProcess(
                argv,
                0,
                b"stdout:" + b"o" * (MAX_VALIDATION_OUTPUT_BYTES + 128),
                b"stderr:" + b"e" * (MAX_VALIDATION_OUTPUT_BYTES + 128),
            )

    monkeypatch.setattr(
        "coquic_steward.execution.container.ValidationContainerRuntime",
        RecordingRuntime,
    )
    executor = StewardExecutor(config, store)
    monkeypatch.setattr(
        "coquic_steward.execution.executor._validation_git_common_dir",
        lambda _worktree: config.repo_root / ".git",
    )
    runner = executor._isolated_validation_runner(task, pipeline, digest)
    for exit_code in (23, 124):
        runtimes[0].exit_code = exit_code
        result = run_validation(
            config,
            "isolated-bounded",
            config.repo_root,
            f"validation-{exit_code}.txt",
            ["verbose-gate"],
            command_runner=runner,
        )
        _assert_bounded_validation_artifact(result, expected_exit_code=exit_code)
    runner.cleanup()

    assert runtimes[0].client.calls[-1]["max_output_bytes"] == MAX_VALIDATION_OUTPUT_BYTES
    assert runtimes[0].cleaned


def test_validation_cleanup_is_durable_before_start_and_retried_after_crash(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "sha256:" + "c" * 64
    deployment = replace(
        config.deployment,
        max_memory_bytes=5 * 1024**3,
        max_pids=321,
        max_scratch_bytes=6 * 1024**3,
        max_log_bytes=7 * 1024**2,
    )
    config = replace(
        config,
        validation_image="coquic-steward-validation",
        validation_image_digest=digest,
        deployment=deployment,
    )
    store = TaskStore.create(config.db_path)
    task, _created = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="validation cleanup",
            prompt="validate",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    store.claim_daemon_instance("daemon-before-crash")
    validation_worktree = config.private_dir / "disposable-worktree"
    validation_worktree.mkdir()
    git_common_dir = config.private_dir / "git-common"
    git_common_dir.mkdir()
    task.worktree_path = validation_worktree
    store.save(task)
    observed_pending: list[dict[str, object]] = []
    cleaned: list[str] = []
    runtime_configs: list[ValidationContainerConfig] = []
    reject_mismatched = False

    class RecordingValidationRuntime(ValidationContainerRuntime):
        def __init__(self, runtime_config, *, docker_bin="docker") -> None:
            super().__init__(runtime_config, docker_bin=docker_bin)
            runtime_configs.append(runtime_config)

        def ensure_started(self) -> str:
            observed_pending.extend(store.list_validation_cleanup_pending())
            return "d" * 64

        def cleanup_owned(self, *, timeout: float = 5) -> None:
            if reject_mismatched and (
                self.config.limits != runtime_configs[0].limits
                or self.config.uid != runtime_configs[0].uid
                or self.config.gid != runtime_configs[0].gid
            ):
                raise RuntimeError("validation policy changed during recovery")
            cleaned.append(self.config.container_name)

    monkeypatch.setattr(
        "coquic_steward.execution.container.ValidationContainerRuntime",
        RecordingValidationRuntime,
    )
    executor = StewardExecutor(config, store)
    monkeypatch.setattr(
        "coquic_steward.execution.executor._validation_git_common_dir",
        lambda _worktree: git_common_dir,
    )
    executor._isolated_validation_runner(task, pipeline, digest)

    assert len(observed_pending) == 1
    assert observed_pending[0]["cleanup_ready"] is False
    assert digest in store.referenced_image_ids()
    root = Path(str(observed_pending[0]["root_path"]))
    assert root.is_dir()

    legacy_record = dict(observed_pending[0])
    legacy_record["git_common_dir_path"] = None
    monkeypatch.setattr(
        "coquic_steward.execution.executor._validation_git_common_dir",
        lambda _worktree: config.repo_root / ".git",
    )
    executor._validation_runtime_for_cleanup(legacy_record)
    assert runtime_configs[-1].git_common_dir == config.repo_root / ".git"

    reject_mismatched = True
    executor.config = replace(
        config,
        deployment=replace(
            deployment,
            host_uid=1001,
            host_gid=1002,
            max_memory_bytes=deployment.max_memory_bytes + 1,
            max_pids=deployment.max_pids + 1,
        ),
    )
    store.claim_daemon_instance("daemon-policy-mismatch")
    assert executor.retry_validation_cleanup_pending() == 0
    assert store.list_validation_cleanup_pending()
    assert root.is_dir()
    assert digest in store.referenced_image_ids()
    executor.config = config
    reject_mismatched = False

    validation_worktree.rmdir()
    monkeypatch.setattr(
        "coquic_steward.execution.executor._validation_git_common_dir",
        lambda _worktree: pytest.fail(
            "cleanup reconstructed Git identity from the removed worktree"
        ),
    )
    store.claim_daemon_instance("daemon-after-crash")
    assert executor.retry_validation_cleanup_pending() == 1
    assert store.list_validation_cleanup_pending() == []
    assert digest not in store.referenced_image_ids()
    assert not root.exists()
    assert cleaned == [str(observed_pending[0]["container_name"])]
    assert len(runtime_configs) == 4
    assert runtime_configs[0].limits == runtime_configs[3].limits
    assert runtime_configs[1].git_common_dir == config.repo_root / ".git"
    assert runtime_configs[2].limits != runtime_configs[0].limits
    assert runtime_configs[3].git_common_dir == git_common_dir
    assert runtime_configs[3].limits == ContainerLimits(
        memory_bytes=deployment.max_memory_bytes,
        pids=deployment.max_pids,
        scratch_bytes=deployment.max_scratch_bytes,
        log_max_bytes=deployment.max_log_bytes,
    )


def test_task_create_argv_has_bounded_restart_and_logs(tmp_path: Path) -> None:
    roots = [
        tmp_path / name
        for name in ("worktree", "archive", "sessions", "git", "common", "scratch")
    ]
    for root in roots:
        root.mkdir()
    config = TaskContainerConfig(
        task_id="task-ops",
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        worktree=roots[0],
        archive=roots[1],
        private_sessions=roots[2],
        git_dir=roots[3],
        git_common_dir=roots[4],
        scratch=roots[5],
        limits=ContainerLimits(log_max_bytes=1024, log_max_files=2),
    )
    argv = TaskContainerRuntime(config).create_argv()
    assert argv[argv.index("--restart") + 1] == "no"
    assert "local" in argv and "max-size=1024b" in argv
    assert "/run:rw,noexec,nosuid,nodev,size=16m" in argv


def test_deployment_runtime_factory_adds_exact_release_and_epoch_labels(
    tmp_path: Path,
) -> None:
    roots = [
        tmp_path / name for name in ("worktree", "archive", "sessions", "git", "common")
    ]
    for root in roots:
        root.mkdir()
    runtime = TaskContainerRuntime(
        TaskContainerConfig(
            task_id="task-deployment",
            image="coquic-steward-task",
            image_digest="sha256:" + "a" * 64,
            worktree=roots[0],
            archive=roots[1],
            private_sessions=roots[2],
            git_dir=roots[3],
            git_common_dir=roots[4],
        )
    )
    config = SimpleNamespace(
        deployment=_deployment(
            tmp_path,
            release_id="release-candidate",
            compose_project="steward-production",
            max_pids=64,
            max_memory_bytes=134_217_728,
            max_log_bytes=1024,
            max_scratch_bytes=2048,
        ),
        ensure_epoch=lambda: {"epochId": "epoch-production"},
    )
    factory = deployment_runtime_factory(config, lambda _task: runtime)

    configured = factory(object())

    assert configured.config.labels["coquic.steward.release"] == "release-candidate"
    assert configured.config.labels["coquic.steward.epoch"] == "epoch-production"
    assert configured.config.labels["coquic.steward.deployment"] == "steward-production"
    assert configured.config.limits.pids == 64
    assert configured.config.limits.memory_bytes == 134_217_728
    assert configured.config.limits.log_max_bytes == 1024
    assert configured.config.limits.scratch_bytes == 2048


def test_deployment_runtime_identity_requires_an_exact_release(tmp_path: Path) -> None:
    roots = [
        tmp_path / name for name in ("worktree", "archive", "sessions", "git", "common")
    ]
    for root in roots:
        root.mkdir()
    runtime = TaskContainerRuntime(
        TaskContainerConfig(
            task_id="task-deployment",
            image="coquic-steward-task",
            image_digest="sha256:" + "a" * 64,
            worktree=roots[0],
            archive=roots[1],
            private_sessions=roots[2],
            git_dir=roots[3],
            git_common_dir=roots[4],
        )
    )
    config = SimpleNamespace(
        deployment=_deployment(tmp_path),
        ensure_epoch=lambda: {"epochId": "epoch-production"},
    )

    with pytest.raises(ValueError, match="exact release identity"):
        bind_deployment_identity(runtime, config)


def test_production_session_factory_binds_task_and_planner_deployment_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repository = home / "repository"
    repository.mkdir(parents=True)
    config = StewardConfig(
        repo_root=repository,
        codex_identity="codex-production",
        task_image_digest="sha256:" + "a" * 64,
        deployment=_deployment(home, release_id="release-cli"),
    )
    config.ensure_dirs()
    monkeypatch.setattr(
        "coquic_steward.execution.container.TaskContainerRuntime.provision_task_paths",
        lambda _self: None,
    )
    store = TaskStore.create(config.db_path)
    supervisor = session_supervisor_for_config(config, store)
    assert supervisor is not None and supervisor.runtime_factory is not None
    assert supervisor.image_digest == config.task_image_digest
    assert supervisor.codex_identity == "codex-production"
    assert session_supervisor_for_config(
        replace(config, task_image_digest=None), store
    ) is None
    task_runtime = supervisor.runtime_factory(
        SimpleNamespace(id="task-cli", worktree_path=repository)
    )
    planner = cli_module._configured_planner_session(config)
    planner_runtime = planner.invoker.runtime

    assert task_runtime.config.labels["coquic.steward.codex"] == "codex-production"
    epoch_id = config.ensure_epoch()["epochId"]
    for runtime in (task_runtime, planner_runtime):
        assert runtime.config.labels["coquic.steward.release"] == "release-cli"
        assert runtime.config.labels["coquic.steward.epoch"] == epoch_id
        assert runtime.config.limits.pids == config.deployment.max_pids
        assert runtime.config.limits.memory_bytes == config.deployment.max_memory_bytes
        assert runtime.config.limits.log_max_bytes == config.deployment.max_log_bytes
        assert runtime.config.limits.scratch_bytes == config.deployment.max_scratch_bytes


def test_release_and_pressure_facts_are_private(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite")
    store.record_image_release(
        "release-test",
        daemon_image_id="sha256:" + "a" * 64,
        task_image_id="sha256:" + "b" * 64,
        labels={"runtime": "task-container-v1"},
        current=True,
    )
    assert store.list_image_releases()[0]["release_id"] == "release-test"
    store.record_resource_pressure(
        state="resource_pressure",
        home_free_bytes=10,
        owned_docker_bytes=20,
        cleanup_pending_count=1,
        reason="threshold",
    )
    assert store.get_resource_pressure()["state"] == "resource_pressure"
    assert "secret" not in json.dumps(store.get_resource_pressure())


@pytest.mark.parametrize("delete_returncode", [0, 1])
def test_labeled_docker_reconciliation_retains_references_and_reclaims_exact_image(
    tmp_path: Path, delete_returncode: int
) -> None:
    daemon_image = "sha256:" + "a" * 64
    task_image = "sha256:" + "b" * 64
    unused_image = "sha256:" + "c" * 64
    candidate_daemon = "sha256:" + "e" * 64
    candidate_task = "sha256:" + "f" * 64
    container_id = "d" * 64
    release_id = "release-owned"
    deployment = _deployment(
        tmp_path,
        release_id=release_id,
        daemon_image_id=daemon_image,
        task_image_id=task_image,
    )
    releases = tmp_path / "private" / "deployment" / "releases"
    releases.mkdir(parents=True)
    (releases.parent / "current").write_text(release_id + "\n", encoding="ascii")
    (releases / f"{release_id}.json").write_text(
        json.dumps(
            {
                "releaseId": release_id,
                "daemonImage": daemon_image,
                "daemonImageId": daemon_image,
                "taskImage": task_image,
                "taskImageId": task_image,
                "runtimeProtocol": "task-container-v1",
            }
        ),
        encoding="utf-8",
    )
    (releases / "release-candidate.json").write_text(
        json.dumps(
            {
                "releaseId": "release-candidate",
                "daemonImage": candidate_daemon,
                "daemonImageId": candidate_daemon,
                "taskImage": candidate_task,
                "taskImageId": candidate_task,
                "runtimeProtocol": "task-container-v1",
            }
        ),
        encoding="utf-8",
    )
    (releases / "release-old.json").write_text(
        json.dumps(
            {
                "releaseId": "release-old",
                "daemonImage": unused_image,
                "daemonImageId": unused_image,
                "taskImage": unused_image,
                "taskImageId": unused_image,
                "runtimeProtocol": "task-container-v1",
            }
        ),
        encoding="utf-8",
    )
    (releases.parent / "operation.journal").write_text(
        json.dumps(
            {
                "phase": "build",
                "outcome": "pending",
                "candidateRelease": "release-candidate",
            }
        ),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def runner(argv: list[str]):
        calls.append(argv)
        command = argv[1:]
        if command[:3] == ["container", "ls", "--all"]:
            assert "label=coquic.steward.deployment=coquic-steward" in command
            output = f"{container_id}\n"
            return subprocess.CompletedProcess(argv, 0, output.encode(), b"")
        if command[:3] == ["container", "inspect", "--size"]:
            payload = [
                {
                    "Id": container_id,
                    "Image": task_image,
                    "SizeRw": 11,
                    "State": {"Status": "exited"},
                    "Config": {
                        "Labels": {
                            "coquic.steward.owner": "steward",
                            "coquic.steward.deployment": "coquic-steward",
                            "coquic.steward.runtime": "task-container-v1",
                            "coquic.steward.release": release_id,
                            "coquic.steward.epoch": "epoch-owned",
                            "coquic.steward.task": "task-owned",
                        }
                    },
                },
            ]
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )
        if command[:2] == ["image", "inspect"]:
            sizes = {
                daemon_image: 20,
                task_image: 30,
                unused_image: 40,
                candidate_daemon: 50,
                candidate_task: 60,
            }
            image_id = command[2]
            payload = [
                {
                    "Id": image_id,
                    "Size": sizes[image_id],
                    "Config": {
                        "Labels": {
                            "coquic.steward.owner": "steward",
                            "coquic.steward.runtime-protocol": "task-container-v1",
                        }
                    },
                }
            ]
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(payload).encode(), b""
            )
        if command[:2] == ["image", "rm"]:
            return subprocess.CompletedProcess(argv, delete_returncode, b"", b"")
        raise AssertionError(argv)

    store = TaskStore.create(tmp_path / "steward.sqlite")
    manager = DockerResourceManager(runner=runner)
    snapshot_calls = 0
    snapshot = manager._snapshot

    def counted_snapshot(image_ids):
        nonlocal snapshot_calls
        snapshot_calls += 1
        return snapshot(image_ids)

    manager._snapshot = counted_snapshot
    result = manager.reconcile(store, deployment)

    assert result["ambiguous"] is False
    expected_reclaimed = (unused_image,) if delete_returncode == 0 else ()
    assert result["reclaimed"] == expected_reclaimed
    assert result["usage"].image_bytes == (160 if delete_returncode == 0 else 200)
    assert result["usage"].image_count == (4 if delete_returncode == 0 else 5)
    assert snapshot_calls == 1
    assert store.list_container_references()[0]["image_id"] == task_image
    assert store.referenced_image_ids() == frozenset({daemon_image, task_image})
    assert ["docker", "image", "rm", unused_image] in calls
    assert not any(call[1:3] == ["image", "ls"] for call in calls)
    assert not any("prune" in value for call in calls for value in call)


def test_ambiguous_docker_snapshot_never_reclaims_images(tmp_path: Path) -> None:
    deployment = _deployment(tmp_path)
    manager = DockerResourceManager()
    manager._snapshot = lambda _image_ids: (
        OwnedDockerUsage(ambiguous=True),
        [],
        [{"image_id": "sha256:" + "a" * 64, "size_bytes": 40}],
        frozenset(),
        True,
    )
    calls: list[list[str]] = []

    def runner(argv: list[str]):
        calls.append(argv)
        raise AssertionError("ambiguous snapshots must not reclaim images")

    manager.runner = runner
    result = manager.reconcile(TaskStore.create(tmp_path / "steward.sqlite"), deployment)

    assert result["ambiguous"] is True
    assert result["reclaimed"] == ()
    assert result["usage"].ambiguous is True
    assert calls == []


@pytest.mark.parametrize("selector_pending", ["previous", "current"])
def test_pending_selector_journal_retains_before_and_after_releases(
    tmp_path: Path, selector_pending: str
) -> None:
    deployment = _deployment(tmp_path)
    deployment_dir = deployment.deployment_dir
    releases = deployment_dir / "releases"
    releases.mkdir(parents=True)
    prior = "release-prior"
    before = "release-before"
    after = "release-after"
    prior_daemon = "sha256:" + "1" * 64
    prior_task = "sha256:" + "2" * 64
    prior_validation = "sha256:" + "3" * 64
    before_daemon = "sha256:" + "a" * 64
    before_task = "sha256:" + "b" * 64
    before_validation = "sha256:" + "c" * 64
    after_daemon = "sha256:" + "d" * 64
    after_task = "sha256:" + "e" * 64
    after_validation = "sha256:" + "f" * 64
    for release_id, daemon, task, validation in (
        (prior, prior_daemon, prior_task, prior_validation),
        (before, before_daemon, before_task, before_validation),
        (after, after_daemon, after_task, after_validation),
    ):
        (releases / f"{release_id}.json").write_text(
            json.dumps(
                {
                    "releaseId": release_id,
                    "daemonImageId": daemon,
                    "taskImageId": task,
                    "validationImageId": validation,
                    "runtimeProtocol": "task-container-v1",
                }
            ),
            encoding="utf-8",
        )
    (deployment_dir / "current").write_text(before + "\n", encoding="ascii")
    (deployment_dir / "previous").write_text(prior + "\n", encoding="ascii")
    (deployment_dir / "operation.journal").write_text(
        json.dumps(
            {
                "phase": "selector",
                "outcome": "pending",
                "operation": "upgrade",
                "fromRelease": before,
                "toRelease": after,
                "selectorPending": selector_pending,
                "beforeCurrent": before,
                "beforePrevious": prior,
                "afterCurrent": after,
                "afterPrevious": before,
            }
        ),
        encoding="utf-8",
    )

    class RecordingStore(TaskStore):
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        def record_image_release(self, release_id: str, **kwargs: object) -> None:
            self.calls.append((release_id, kwargs))

    store = RecordingStore()
    release_images, in_flight = DockerResourceManager._record_deployment_releases(
        store, deployment
    )

    assert set(in_flight) == {prior, before, after}
    assert set(release_images) == {prior, before, after}
    assert {release_id for release_id, _kwargs in store.calls} == {prior, before, after}
    assert all(
        kwargs["current"] is (release_id == before)
        for release_id, kwargs in store.calls
    )


@pytest.mark.parametrize("outcome", [None, "success", "unknown"])
def test_reserved_selector_journal_requires_pending_outcome(
    tmp_path: Path, outcome: str | None
) -> None:
    deployment = _deployment(tmp_path)
    deployment_dir = deployment.deployment_dir
    assert deployment_dir is not None
    deployment_dir.mkdir(parents=True)
    journal = {"phase": "selector"}
    if outcome is not None:
        journal["outcome"] = outcome
    (deployment_dir / "operation.journal").write_text(
        json.dumps(journal), encoding="utf-8"
    )

    class RecordingStore(TaskStore):
        def __init__(self) -> None:
            pass

        def record_image_release(self, _release_id: str, **_kwargs: object) -> None:
            raise AssertionError("selector journal should fail before release recording")

    with pytest.raises(ValueError, match="selector journal outcome"):
        DockerResourceManager._record_deployment_releases(
            RecordingStore(), deployment
        )


def test_non_selector_success_journal_remains_ignorable(tmp_path: Path) -> None:
    deployment = _deployment(tmp_path)
    deployment_dir = deployment.deployment_dir
    assert deployment_dir is not None
    deployment_dir.mkdir(parents=True)
    (deployment_dir / "operation.journal").write_text(
        json.dumps({"phase": "complete", "outcome": "success"}),
        encoding="utf-8",
    )

    class RecordingStore(TaskStore):
        def __init__(self) -> None:
            pass

        def record_image_release(self, _release_id: str, **_kwargs: object) -> None:
            raise AssertionError("there are no release records to record")

    assert DockerResourceManager._record_deployment_releases(
        RecordingStore(), deployment
    ) == ({}, frozenset())


def test_health_fails_closed_when_database_state_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()

    class BrokenStore:
        @classmethod
        def open(cls, _path: Path):
            raise OSError("private database detail")

    monkeypatch.setattr(cli_module, "load_config", lambda **_kwargs: config)
    monkeypatch.setattr(cli_module, "TaskStore", BrokenStore)
    result = CliRunner().invoke(cli_module.app, ["health"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["quiescent"] is False
    assert payload["lifecycle"] == "ambiguous"
    assert payload["heartbeat"] == "degraded"
    assert payload["activeTasks"] is None
    assert payload["cleanupPending"] is None
    assert payload["containerCounts"] is None
    assert "private database detail" not in result.stdout


def test_health_is_not_quiescent_with_pending_archive_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    store.claim_daemon_instance(
        "daemon-health-test", lifecycle="running",
        state={
            "heartbeat_at": datetime.now(timezone.utc).isoformat(),
            "runtime_protocol": config.runtime_protocol,
        },
    )
    store.control_loop_ledger.record_runtime("running")
    assert store.control_loop_ledger.outbox(limit=1)

    monkeypatch.setattr(cli_module, "load_config", lambda **_kwargs: config)
    result = CliRunner().invoke(cli_module.app, ["health"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["archivePending"] is True
    assert payload["quiescent"] is False


def test_health_uses_canonical_retryable_cleanup_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = StewardConfig(repo_root=tmp_path, local_codex_test_harness=True)
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    store.claim_daemon_instance(
        "daemon-health-test", lifecycle="running",
        state={
            "heartbeat_at": datetime.now(timezone.utc).isoformat(),
            "runtime_protocol": config.runtime_protocol,
        },
    )
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="retryable cleanup",
            prompt="prompt",
        )
    )
    store.add_event(task.id, "cleanup_retryable", "container stop incomplete")

    def fail_scan(*_args: object, **_kwargs: object):
        pytest.fail("health scanned task or event history")

    monkeypatch.setattr(store, "list_tasks", fail_scan)
    monkeypatch.setattr(store, "events", fail_scan)
    monkeypatch.setattr(cli_module, "TaskStore", SimpleNamespace(open=lambda _path: store))
    monkeypatch.setattr(cli_module, "load_config", lambda **_kwargs: config)

    result = CliRunner().invoke(cli_module.app, ["health"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["cleanupPending"] == 1
    assert payload["quiescent"] is False

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

    assert len(commands) == 5
    assert commands[-1] == ["steward-task-validate", str(worktree)]
    assert all(command[: len(prefix)] == prefix for command in commands[:4])
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

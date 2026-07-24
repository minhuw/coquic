"""The sole Docker command boundary for task execution.

Only this module is allowed to construct Docker argv.  The default client uses
the Docker CLI so tests can substitute a recording fake without a Docker SDK.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess  # nosec B404 - explicit argv, shell=False below
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from ..core.subprocesses import current_subprocess_owner
from .container_config import (
    ContainerMount,
    PlannerContainerConfig,
    TaskContainerConfig,
    TaskRole,
)


class ContainerErrorCategory(StrEnum):
    not_found = "not-found"
    runtime_unavailable = "runtime-unavailable"
    identity_mismatch = "identity-mismatch"
    timeout = "timeout"
    ambiguous = "ambiguous"
    invalid = "invalid"
    rejected = "rejected"


class ContainerBoundaryError(RuntimeError):
    def __init__(self, category: ContainerErrorCategory, message: str):
        super().__init__(message)
        self.category = category


ContainerError = ContainerBoundaryError


@dataclass(frozen=True)
class ContainerInspection:
    container_id: str
    name: str
    state: str
    running: bool
    labels: dict[str, str]
    image: str | None = None
    image_digest: str | None = None
    pid: int | None = None
    raw: Any = None


@dataclass(frozen=True)
class ExecIdentity:
    container_id: str
    exec_id: str
    pid: int | None = None
    uid: int | None = None


@dataclass(frozen=True)
class ExecResult:
    identity: ExecIdentity
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""


class DockerClient(Protocol):
    def run(self, argv: list[str], *, input: bytes | None = None, timeout: float | None = None) -> subprocess.CompletedProcess[bytes]: ...


class SubprocessDockerClient:
    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin

    def run(
        self,
        argv: list[str],
        *,
        input: bytes | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        process = subprocess.Popen(  # nosec B603 - argv is validated by caller
            [self.docker_bin, *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input is not None else None,
            shell=False,
            start_new_session=True,
        )
        owner = current_subprocess_owner()
        if owner is not None:
            owner.register(process)
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _terminate_docker_group(process, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                _terminate_docker_group(process, signal.SIGKILL)
                stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(
                [self.docker_bin, *argv],
                timeout,
                output=stdout,
                stderr=stderr,
            ) from exc
        finally:
            if owner is not None:
                owner.unregister(process)
        return subprocess.CompletedProcess(
            [self.docker_bin, *argv], process.returncode, stdout, stderr
        )

    def popen(self, argv: list[str]) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(  # nosec B603 - argv is validated by caller
            [self.docker_bin, *argv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        owner = current_subprocess_owner()
        if owner is not None:
            owner.register(process)

            def unregister() -> None:
                try:
                    process.wait()
                finally:
                    owner.unregister(process)

            import threading

            threading.Thread(
                target=unregister,
                name="steward-docker-exec-reaper",
                daemon=True,
            ).start()
        return process


class TaskContainerRuntime:
    """Create/adopt one reusable task container and execute role processes."""

    def __init__(
        self,
        config: TaskContainerConfig,
        *,
        client: DockerClient | None = None,
        docker_bin: str = "docker",
    ):
        self.config = config
        self.client = client or SubprocessDockerClient(docker_bin)

    def create(self) -> str:
        argv = self.create_argv()
        result = self._run(argv)
        container_id = result.stdout.decode("utf-8", "replace").strip()
        if not container_id:
            raise ContainerBoundaryError(
                ContainerErrorCategory.ambiguous,
                "Docker create returned no container identity",
            )
        return container_id

    def create_argv(self) -> list[str]:
        config = self.config
        argv = [
            "create",
            "--name",
            config.container_name,
            "--init",
            "--network",
            config.network,
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            str(config.limits.pids),
            "--memory",
            str(config.limits.memory_bytes),
        ]
        for key in sorted(config.labels):
            argv.extend(["--label", f"{key}={config.labels[key]}"])
        # Both worktree views and the bounded scratch path are fixed at create
        # time. Kernel DAC plus the per-exec role group selects which
        # writable view a role can actually use.
        for mount in config.mounts_for(TaskRole.implementation):
            argv.extend(self._mount_argv(mount))
        # A private tmpfs is the only writable filesystem before a role exec.
        argv.extend(
            [
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size="
                + str(config.limits.scratch_bytes),
            ]
        )
        argv.append(config.image_digest)
        return argv

    def adopt(self, *, expected_id: str | None = None) -> ContainerInspection:
        inspection = self.inspect()
        if expected_id is not None and inspection.container_id != expected_id:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "adopted container id does not match persisted identity",
            )
        self._validate_inspection(inspection)
        return inspection

    def start(self, container_id: str | None = None) -> None:
        identifier = container_id or self.config.container_name
        self._run(["start", identifier])

    def ensure_started(self) -> str:
        try:
            inspection = self.inspect()
        except ContainerBoundaryError as exc:
            if exc.category is not ContainerErrorCategory.not_found:
                raise
            identifier = self.create()
            self.start(identifier)
            return identifier
        self._validate_inspection(inspection)
        if not inspection.running:
            self.start(inspection.container_id)
        return inspection.container_id

    def inspect(self) -> ContainerInspection:
        result = self._run(
            [
                "inspect",
                "--format",
                "{{json .}}",
                self.config.container_name,
            ],
            allow_not_found=True,
        )
        if result.returncode != 0:
            if _not_found(result.stderr):
                raise ContainerBoundaryError(
                    ContainerErrorCategory.not_found,
                    f"task container not found: {self.config.container_name}",
                )
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )
        try:
            value = json.loads(result.stdout.decode("utf-8"))
            if isinstance(value, list):
                value = value[0]
            state = value.get("State") or {}
            config = value.get("Config") or {}
            labels = dict(config.get("Labels") or {})
            return ContainerInspection(
                container_id=str(value.get("Id") or ""),
                name=self.config.container_name,
                state=str(state.get("Status") or "unknown"),
                running=bool(state.get("Running")),
                labels={str(k): str(v) for k, v in labels.items()},
                image=str(config.get("Image")) if config.get("Image") else None,
                image_digest=labels.get("coquic.steward.image-digest"),
                pid=int(state["Pid"]) if state.get("Pid") else None,
                raw=value,
            )
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.ambiguous,
                "Docker inspect returned malformed task identity",
            ) from exc

    def exec_argv(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        interactive: bool = False,
    ) -> list[str]:
        if not command or any("\x00" in item for item in command):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid, "container exec command is empty or invalid"
            )
        selected = TaskRole(role)
        allowed = self.config.environment(
            selected, session_uid=session_uid, session_id=session_id
        )
        supplied = dict(env or {})
        for key, value in supplied.items():
            if key in {"CODEX_API_KEY", "HOME", "CODEX_HOME"}:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid,
                    f"caller cannot override protected environment {key}",
                )
            if "\x00" in key or "\x00" in value:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid, "invalid exec environment"
                )
            allowed[key] = value
        argv = [
            "exec",
            "--user",
            f"{session_uid}:{self._role_gid(selected, session_uid)}",
            "--workdir",
            workdir or (self.config.container_worktree_rw if selected.can_write_worktree else self.config.container_worktree_ro),
        ]
        if interactive:
            argv.extend(["--interactive"])
        for key in sorted(allowed):
            argv.extend(["--env", f"{key}={allowed[key]}"])
        argv.extend([self.config.container_name, *command])
        return argv

    def _role_gid(self, role: TaskRole, session_uid: int) -> int:
        if role.can_write_worktree:
            return self.config.task_write_gid
        if role.needs_scratch:
            return self.config.validation_gid
        return session_uid

    def exec(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        timeout: float | None = None,
    ) -> ExecResult:
        argv = self.exec_argv(
            role,
            session_uid=session_uid,
            session_id=session_id,
            command=command,
            env=env,
            workdir=workdir,
        )
        result = self._run(argv, timeout=timeout)
        identity = ExecIdentity(self.config.container_name, _exec_id(result) or "unknown")
        return ExecResult(identity, result.returncode, result.stdout, result.stderr)

    def exec_stream(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> subprocess.Popen[bytes]:
        argv = self.exec_argv(
            role,
            session_uid=session_uid,
            session_id=session_id,
            command=command,
            env=env,
            workdir=workdir,
            interactive=True,
        )
        popen = getattr(self.client, "popen", None)
        if popen is None:
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                "Docker client does not support streaming exec",
            )
        return popen(argv)

    def signal(self, identity: ExecIdentity, sig: int | signal.Signals) -> None:
        self._validate_exec_identity(identity)
        # Docker has no portable signal-by-exec-id command. The trusted wrapper
        # records its in-container PID before replacing itself with Codex.
        self._run(
            [
                "exec",
                "--user",
                str(identity.uid),
                "--env",
                f"COQUIC_STEWARD_SIGNAL={int(sig)}",
                self.config.container_name,
                "/bin/task-entrypoint.sh",
                "signal",
                str(identity.pid),
            ]
        )

    def exec_is_live(self, identity: ExecIdentity) -> bool:
        """Probe the persisted wrapper PID without treating container liveness as enough."""

        self._validate_exec_identity(identity)
        result = self._run(
            [
                "exec",
                "--user",
                str(identity.uid),
                "--env",
                "COQUIC_STEWARD_SIGNAL=0",
                self.config.container_name,
                "/bin/task-entrypoint.sh",
                "signal",
                str(identity.pid),
            ],
            allow_not_found=True,
        )
        if result.returncode == 0:
            return True
        if _process_not_found(result.stderr):
            return False
        category = (
            ContainerErrorCategory.not_found
            if _not_found(result.stderr)
            else ContainerErrorCategory.runtime_unavailable
        )
        raise ContainerBoundaryError(category, _decode_error(result.stderr))

    def stop(self, container_id: str | None = None, *, timeout: float | None = None) -> None:
        identifier = container_id or self.config.container_name
        result = self._run(
            ["stop", "--time", str(max(1, int(timeout or 10))), identifier],
            allow_not_found=True,
            timeout=timeout,
        )
        if result.returncode and not _not_found(result.stderr):
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )

    def remove(self, container_id: str | None = None) -> None:
        """Remove one stopped, identity-validated task container.

        This is deliberately separate from :meth:`stop`: graceful daemon
        shutdown retains stopped containers, while terminal cleanup removes
        them only after the public archive has been sealed and verified.
        """

        identifier = container_id or self.config.container_name
        try:
            inspection = self.adopt(expected_id=container_id)
        except ContainerBoundaryError as exc:
            if exc.category is ContainerErrorCategory.not_found:
                return
            raise
        if inspection.running:
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "task container must be stopped before removal",
            )
        result = self._run(["rm", identifier], allow_not_found=True)
        if result.returncode and not _not_found(result.stderr):
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                _decode_error(result.stderr),
            )

    def _mount_argv(self, mount: ContainerMount) -> list[str]:
        source = str(mount.source)
        if any(char in source for char in "\x00\n"):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid, "mount source contains control characters"
            )
        value = f"type=bind,src={source},dst={mount.target}"
        if mount.read_only:
            value += ",readonly"
        return ["--mount", value]

    def _validate_inspection(self, inspection: ContainerInspection) -> None:
        if inspection.name != self.config.container_name:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "container name does not match task identity",
            )
        expected = self.config.image_digest
        actual = inspection.image_digest
        if actual is not None and actual != expected:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "container image digest does not match locked task image",
            )
        for key, expected_value in self.config.labels.items():
            if inspection.labels.get(key) != expected_value:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.identity_mismatch,
                    f"container label mismatch: {key}",
                )

    def _validate_exec_identity(self, identity: ExecIdentity) -> None:
        if identity.container_id != self.config.container_name:
            raise ContainerBoundaryError(
                ContainerErrorCategory.identity_mismatch,
                "exec identity belongs to another task container",
            )
        if (
            identity.pid is None
            or identity.pid <= 1
            or identity.uid is None
            or not 10000 <= identity.uid <= 60000
        ):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "exec identity does not contain a validated wrapper PID",
            )

    def _run(
        self,
        argv: list[str],
        *,
        input: bytes | None = None,
        timeout: float | None = None,
        allow_not_found: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            result = self.client.run(argv, input=input, timeout=timeout)
        except FileNotFoundError as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.runtime_unavailable,
                "Docker executable is unavailable",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ContainerBoundaryError(
                ContainerErrorCategory.timeout,
                "Docker command timed out",
            ) from exc
        if result.returncode and not allow_not_found:
            if _not_found(result.stderr):
                category = ContainerErrorCategory.not_found
            else:
                category = ContainerErrorCategory.runtime_unavailable
            raise ContainerBoundaryError(category, _decode_error(result.stderr))
        return result


class PlannerContainerRuntime(TaskContainerRuntime):
    """Reusable container with only sealed history and private planner mounts."""

    config: PlannerContainerConfig

    def __init__(
        self,
        config: PlannerContainerConfig,
        *,
        client: DockerClient | None = None,
        docker_bin: str = "docker",
    ):
        self.config = config
        self.client = client or SubprocessDockerClient(docker_bin)

    def create_argv(self) -> list[str]:
        config = self.config
        argv = [
            "create",
            "--name",
            config.container_name,
            "--init",
            "--network",
            config.network,
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            str(config.limits.pids),
            "--memory",
            str(config.limits.memory_bytes),
        ]
        for key in sorted(config.labels):
            argv.extend(["--label", f"{key}={config.labels[key]}"])
        for mount in config.mounts:
            argv.extend(self._mount_argv(mount))
        argv.extend(
            [
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size="
                + str(config.limits.scratch_bytes),
                config.image_digest,
            ]
        )
        return argv

    def exec_argv(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        interactive: bool = False,
    ) -> list[str]:
        if TaskRole(role) is not TaskRole.planner:
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid,
                "planner container accepts only planner executions",
            )
        if not command or any("\x00" in item for item in command):
            raise ContainerBoundaryError(
                ContainerErrorCategory.invalid, "container exec command is empty or invalid"
            )
        allowed = self.config.environment(
            role, session_uid=session_uid, session_id=session_id
        )
        for key, value in dict(env or {}).items():
            if key in {"CODEX_API_KEY", "HOME", "CODEX_HOME"}:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid,
                    f"caller cannot override protected environment {key}",
                )
            if "\x00" in key or "\x00" in value:
                raise ContainerBoundaryError(
                    ContainerErrorCategory.invalid, "invalid exec environment"
                )
            allowed[key] = value
        argv = [
            "exec",
            "--user",
            f"{session_uid}:{session_uid}",
            "--workdir",
            workdir or self.config.container_history,
        ]
        if interactive:
            argv.append("--interactive")
        for key in sorted(allowed):
            argv.extend(["--env", f"{key}={allowed[key]}"])
        argv.extend([self.config.container_name, *command])
        return argv


ContainerRuntime = TaskContainerRuntime
DockerBoundary = TaskContainerRuntime


def _not_found(value: bytes) -> bool:
    text = value.decode("utf-8", "replace").lower()
    return (
        "no such container" in text
        or "no such object" in text
        or "not found" in text
    )


def _terminate_docker_group(process: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def _process_not_found(value: bytes) -> bool:
    text = value.decode("utf-8", "replace").lower()
    return "no such process" in text


def _decode_error(value: bytes) -> str:
    return value.decode("utf-8", "replace").strip()[-2000:] or "Docker command failed"


def _exec_id(result: subprocess.CompletedProcess[bytes]) -> str | None:
    # A fake boundary may return the Docker exec identity as JSON or text.  The
    # real CLI output is intentionally not treated as a process identity.
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(value, dict) and isinstance(value.get("Id"), str):
        return value["Id"]
    return None

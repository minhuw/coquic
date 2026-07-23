"""One restricted rsync operation for Steward's raw task archive.

The synchronizer intentionally has no scheduler, task selection, archive
projection, or Site V2 acknowledgement.  It validates the filesystem boundary,
claims one health row, launches exactly one rsync subprocess, and records only
bounded operational health.
"""

from __future__ import annotations

import inspect
import math
import os
import re
import shlex
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Sequence
from uuid import uuid4

from .task_archive_sync_config import (
    TASK_ARCHIVE_SYNC_CONFIG_PATH,
    TASK_ARCHIVE_SYNC_MODULE,
    TaskArchiveSyncConfig,
    TaskArchiveSyncHealth,
    bounded_safe_detail,
    validate_cycle_id,
)


class TaskArchiveSyncCategory(StrEnum):
    success = "success"
    incomplete = "incomplete"
    busy = "busy"
    disabled = "disabled"
    cancelled = "cancelled"
    interrupted = "interrupted"
    timeout = "timeout"
    ssh_auth = "ssh_auth"
    ssh = "ssh_auth"
    host_key = "host_key"
    permission = "permission"
    permissions = "permission"
    receiver_policy = "receiver_policy"
    remote_space = "remote_space"
    transport = "transport"
    source_invariant = "source_invariant"
    unknown = "unknown"


class TaskArchiveSyncCancelled(RuntimeError):
    """Raised by an injected runner or cancellation hook to stop a cycle."""


class TaskArchiveSyncSourceError(RuntimeError):
    """The source tree contains unsupported or unsafe filesystem state."""


class TaskArchiveSyncReceiverError(ValueError):
    """A forced receiver command or path violates the write-only boundary."""


_RECEIVER_REFUSED_OPTIONS = (
    "delete delete-excluded delete-delay delete-before delete-during delete-after "
    "remove-source-files inplace append append-verify partial partial-dir "
    "delay-updates links hard-links devices specials D owner group perms "
    "acls xattrs"
)
_RECEIVER_HIDDEN_EXCLUDES = ".* .*/ ~*"
_PROCESS_WAIT_SLICE_SECONDS = 0.05
_PROCESS_STOP_GRACE_SECONDS = 1.0


def _receiver_root(task_root: Path) -> Path:
    root = Path(task_root).expanduser()
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts):
        raise TaskArchiveSyncReceiverError("receiver root must be an absolute clean path")
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise TaskArchiveSyncReceiverError("receiver root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise TaskArchiveSyncReceiverError("receiver root must be an absolute directory")
    if stat.S_ISLNK(metadata.st_mode):
        raise TaskArchiveSyncReceiverError("receiver root must not be a symlink")
    return root


def build_receiver_rsyncd_config(
    task_root: Path,
    *,
    module: str = TASK_ARCHIVE_SYNC_MODULE,
) -> str:
    """Return the fixed write-only daemon module configuration.

    The resulting text is intended for the operator-managed receiver image or
    the fake protocol harness.  It contains no source data or credentials.
    """

    if module != TASK_ARCHIVE_SYNC_MODULE:
        raise TaskArchiveSyncReceiverError("receiver module is fixed")
    root = _receiver_root(task_root)
    return (
        "use chroot = no\n"
        "read only = no\n"
        "write only = yes\n"
        "list = no\n"
        "reverse lookup = no\n"
        f"refuse options = {_RECEIVER_REFUSED_OPTIONS}\n"
        f"exclude = {_RECEIVER_HIDDEN_EXCLUDES}\n"
        f"[{TASK_ARCHIVE_SYNC_MODULE}]\n"
        f"path = {root}\n"
        "read only = no\n"
        "write only = yes\n"
        "list = no\n"
        f"refuse options = {_RECEIVER_REFUSED_OPTIONS}\n"
        f'pre-xfer exec = /usr/bin/test "$RSYNC_REQUEST" = "{TASK_ARCHIVE_SYNC_MODULE}/"\n'
        f"exclude = {_RECEIVER_HIDDEN_EXCLUDES}\n"
    )


build_fixed_receiver_config = build_receiver_rsyncd_config


def validate_receiver_upload(
    module: str,
    relative_path: str,
    *,
    options: Sequence[str] = (),
) -> Path:
    """Validate module/path/options used by the fake daemon protocol harness."""

    if module != TASK_ARCHIVE_SYNC_MODULE:
        raise TaskArchiveSyncReceiverError("receiver module is not allowed")
    if relative_path not in {"", ".", "./"}:
        validate_receiver_relative_path(relative_path, Path("/fixed/steward-tasks"))
        raise TaskArchiveSyncReceiverError("receiver upload must target the module root")
    forbidden = {
        "delete",
        "delete-excluded",
        "delete-delay",
        "delete-before",
        "delete-during",
        "delete-after",
        "remove-source-files",
        "inplace",
        "append",
        "append-verify",
        "partial",
        "partial-dir",
        "delay-updates",
        "links",
        "hard-links",
        "devices",
        "specials",
        "owner",
        "group",
        "perms",
        "acls",
        "xattrs",
    }
    for option in options:
        token = str(option).lstrip("-").split("=", 1)[0]
        if token in forbidden:
            raise TaskArchiveSyncReceiverError("receiver option is refused")
    return Path(".")


@dataclass(frozen=True, slots=True)
class FakeTaskArchiveReceiver:
    """Policy harness for tests that exercise real rsync daemon framing.

    Tests may launch ``rsync --daemon --config=<config>`` using
    :meth:`config_text`; this object only validates the SSH forced command and
    the fixed module root, leaving protocol framing to the installed rsync.
    """

    task_root: Path
    module: str = TASK_ARCHIVE_SYNC_MODULE
    config_path: str = TASK_ARCHIVE_SYNC_CONFIG_PATH

    def __post_init__(self) -> None:
        _receiver_root(self.task_root)
        if self.module != TASK_ARCHIVE_SYNC_MODULE:
            raise ValueError("receiver module is fixed")
        config_path = str(self.config_path)
        config = Path(config_path)
        if not config.is_absolute() or any(
            character in config_path for character in ("\x00", "\n", "\r", '"')
        ):
            raise ValueError("receiver config path must be an absolute safe path")
        object.__setattr__(self, "config_path", config_path)

    @property
    def forced_command(self) -> str:
        return (
            f"/usr/bin/rsync --server --daemon --config={self.config_path} ."
        )

    @property
    def config_text(self) -> str:
        return build_receiver_rsyncd_config(self.task_root, module=self.module)

    def daemon_argv(self) -> list[str]:
        """Command used by a fake receiver process for real rsync framing."""

        return [
            "/usr/bin/rsync",
            "--server",
            "--daemon",
            f"--config={self.config_path}",
            ".",
        ]

    def accept_command(self, command: str) -> tuple[str, ...]:
        return validate_forced_receiver_command(command, config_path=self.config_path)

    def accept_upload(
        self,
        module: str,
        relative_path: str = ".",
        *,
        options: Sequence[str] = (),
    ) -> Path:
        validate_receiver_upload(module, relative_path, options=options)
        return Path(self.task_root)


ReceiverHarness = FakeTaskArchiveReceiver


@dataclass(frozen=True, slots=True)
class TaskArchiveSyncClassification:
    category: str
    success: bool
    retryable: bool
    exit_code: int | None
    safe_detail: str

    @property
    def incomplete(self) -> bool:
        return self.category == TaskArchiveSyncCategory.incomplete


@dataclass(frozen=True, slots=True)
class TaskArchiveSyncResult:
    cycle_id: str | None
    status: str
    category: str
    success: bool
    retryable: bool
    exit_code: int | None = None
    duration_seconds: float | None = None
    safe_detail: str | None = None
    health: TaskArchiveSyncHealth | None = None

    @property
    def completed(self) -> bool:
        return self.status in {"success", "incomplete", "failure", "cancelled"}

    @property
    def incomplete(self) -> bool:
        return self.category == TaskArchiveSyncCategory.incomplete

    @property
    def busy(self) -> bool:
        return self.category == TaskArchiveSyncCategory.busy

    @property
    def exit_category(self) -> str:
        return self.category

    @property
    def failure_category(self) -> str:
        return self.category


@dataclass(frozen=True, slots=True)
class ForcedReceiverPolicy:
    """Validation rules represented by the fixed daemon-over-SSH key."""

    task_root: Path
    rsync_path: str = "/usr/bin/rsync"
    config_path: str = TASK_ARCHIVE_SYNC_CONFIG_PATH
    module: str = TASK_ARCHIVE_SYNC_MODULE

    def __post_init__(self) -> None:
        root = Path(self.task_root).expanduser()
        if (
            not root.is_absolute()
            or not root.name
            or any(part in {".", ".."} for part in root.parts)
        ):
            raise ValueError("task_root must be an absolute path")
        if not self.rsync_path.startswith("/") or any(
            character in self.rsync_path for character in ('"', "'", "\n", "\x00")
        ):
            raise ValueError("rsync_path must be an absolute executable path")
        if self.rsync_path != "/usr/bin/rsync":
            raise ValueError("rsync_path is fixed to the locked rsync executable")
        if self.config_path != TASK_ARCHIVE_SYNC_CONFIG_PATH:
            raise ValueError("config_path is fixed to the receiver daemon config")
        if self.module != TASK_ARCHIVE_SYNC_MODULE:
            raise ValueError("module is fixed to the task archive module")
        object.__setattr__(self, "task_root", root)

    @property
    def forced_command(self) -> str:
        return (
            f"{self.rsync_path} --server --daemon "
            f"--config={self.config_path} ."
        )

    def authorized_key_line(self, public_key: str) -> str:
        return build_forced_receiver_authorized_key(
            public_key,
            self.task_root,
            rsync_path=self.rsync_path,
            config_path=self.config_path,
            module=self.module,
        )

    def validate_command(self, original_command: str) -> tuple[str, ...]:
        return validate_forced_receiver_command(original_command)

    def validate_relative_path(self, relative_path: str) -> Path:
        return validate_receiver_relative_path(relative_path, self.task_root)


def build_forced_receiver_authorized_key(
    public_key: str,
    task_root: Path,
    *,
    rsync_path: str = "/usr/bin/rsync",
    config_path: str = TASK_ARCHIVE_SYNC_CONFIG_PATH,
    module: str = TASK_ARCHIVE_SYNC_MODULE,
    # Kept as a rejected compatibility spelling so stock rrsync cannot
    # accidentally be reintroduced at a call site.
    rrsync_path: str | None = None,
) -> str:
    """Build a fake-test authorized-key line without generating/installing keys."""

    if not isinstance(public_key, str) or not public_key.strip():
        raise ValueError("public_key is required")
    key = public_key.strip()
    if any(character in key for character in ('\n', '\r', '"')):
        raise ValueError("public_key contains unsupported characters")
    if rrsync_path is not None:
        raise ValueError("rrsync forced commands are unsupported; use daemon-over-SSH")
    policy = ForcedReceiverPolicy(
        Path(task_root),
        rsync_path=rsync_path,
        config_path=config_path,
        module=module,
    )
    return f'restrict,command="{policy.forced_command}" {key}'


def validate_receiver_relative_path(relative_path: str, task_root: Path) -> Path:
    """Resolve a receiver-relative path while rejecting escape and absolutes."""

    if not isinstance(relative_path, str) or not relative_path:
        raise TaskArchiveSyncReceiverError("receiver path is required")
    if "\x00" in relative_path or "\\" in relative_path:
        raise TaskArchiveSyncReceiverError("receiver path contains unsupported bytes")
    candidate = Path(relative_path)
    if candidate.is_absolute() or relative_path.startswith("~"):
        raise TaskArchiveSyncReceiverError("receiver path must be relative")
    root = Path(task_root).resolve()
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise TaskArchiveSyncReceiverError("receiver path escapes fixed root") from exc
    return resolved


_FORBIDDEN_RECEIVER_TOKENS = (
    "delete",
    "remove-source",
    "inplace",
    "append",
    "partial",
    "delay-updates",
    "relative",
    "links",
    "hard-links",
    "devices",
    "specials",
    "owner",
    "group",
    "perms",
    "acls",
    "xattrs",
)


def validate_forced_receiver_command(
    original_command: str,
    *,
    rsync_path: str = "/usr/bin/rsync",
    config_path: str = TASK_ARCHIVE_SYNC_CONFIG_PATH,
) -> tuple[str, ...]:
    """Validate the exact fixed daemon command sent to the SSH receiver."""

    if not isinstance(original_command, str) or not original_command.strip():
        raise TaskArchiveSyncReceiverError("empty forced receiver command")
    if any(character in original_command for character in ("\x00", "\n", "\r")):
        raise TaskArchiveSyncReceiverError("receiver command contains control bytes")
    try:
        tokens = tuple(shlex.split(original_command, posix=True))
    except ValueError as exc:
        raise TaskArchiveSyncReceiverError("receiver command is not shell-safe") from exc
    expected = (
        rsync_path,
        "--server",
        "--daemon",
        f"--config={config_path}",
        ".",
    )
    if tokens != expected:
        raise TaskArchiveSyncReceiverError("receiver command is not the fixed daemon invocation")
    return tokens


def _is_hidden(name: str) -> bool:
    return name.startswith(".") or name.startswith("~")


def validate_source_tree(tasks_dir: Path) -> None:
    """Validate only the canonical source root.

    Rsync's recursive mode transfers regular files and directories while
    skipping symlinks and special files when link/device preservation is not
    requested.  A mixed tree is therefore valid and is deliberately left to
    rsync's per-entry handling instead of aborting a whole cycle up front.
    """

    root = Path(tasks_dir)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise TaskArchiveSyncSourceError("source task root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise TaskArchiveSyncSourceError("source task root is not a directory")


def build_ssh_argv(config: TaskArchiveSyncConfig) -> list[str]:
    """Build strict SSH transport options for rsync's daemon-over-SSH mode."""

    timeout = str(max(1, math.ceil(config.connect_timeout_seconds)))
    return [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RequestTTY=no",
        "-o",
        f"ConnectTimeout={timeout}",
        "-i",
        str(config.identity_path),
        "-o",
        f"UserKnownHostsFile={config.known_hosts_path}",
        "-p",
        str(config.remote_port),
    ]


def build_rsync_argv(config: TaskArchiveSyncConfig) -> list[str]:
    """Build one recursive transfer to the fixed daemon module.

    The destination uses rsync's ``host::module`` daemon syntax.  The SSH
    receiver key supplies the locked daemon command and config, so the client
    has no remote shell/config/module path to choose.
    """

    source = str(config.tasks_dir)
    if not source.endswith(os.sep):
        source += os.sep
    destination = (
        f"{config.remote_user}@{config.remote_host}::"
        f"{config.receiver_module}"
    )
    ssh_command = shlex.join(build_ssh_argv(config))
    argv = [
        "rsync",
        "--recursive",
        "--times",
        "--protect-args",
        "--modify-window=-1",
        f"--timeout={max(1, math.ceil(config.transfer_timeout_seconds))}",
        "--exclude=.*",
        "--exclude=*/.*",
        "--exclude=~*",
        "--rsh",
        ssh_command,
        source,
        destination,
    ]
    _assert_safe_rsync_argv(argv)
    return argv


_FORBIDDEN_SHORT_RSYNC_FLAGS = frozenset("aAlLDogpHKRX")


def _assert_safe_rsync_argv(argv: Sequence[str]) -> None:
    forbidden = (
        "--archive",
        "--delete",
        "--remove",
        "--inplace",
        "--append",
        "--partial",
        "--delay-updates",
        "--rsync-path",
        "--files-from",
        "--relative",
        "--copy-links",
        "--copy-unsafe-links",
        "--safe-links",
        "--munge-links",
        "--links",
        "--devices",
        "--specials",
        "--owner",
        "--group",
        "--acls",
        "--xattrs",
    )
    for token in argv:
        raw = str(token)
        lowered = raw.lower()
        if lowered in {
            "-a",
            "-rlptgo",
            "-rlptgod",
            "-D",
            "-g",
            "-o",
            "-p",
            "-h",
            "-x",
        } or any(
            lowered == item or lowered.startswith(item + "=") for item in forbidden
        ):
            raise TaskArchiveSyncReceiverError("rsync argv contains a forbidden option")
        if raw.startswith("-") and not raw.startswith("--"):
            if any(flag in raw[1:] for flag in _FORBIDDEN_SHORT_RSYNC_FLAGS):
                raise TaskArchiveSyncReceiverError(
                    "rsync argv contains a forbidden option"
                )
        if lowered.startswith("--remove") or lowered.startswith("--delete"):
            raise TaskArchiveSyncReceiverError("rsync argv contains a deletion option")
    if not argv or argv[0] != "rsync":
        raise TaskArchiveSyncReceiverError("argv must invoke rsync directly")
    if len(argv) < 3:
        raise TaskArchiveSyncReceiverError("rsync argv is incomplete")
    destination = str(argv[-1])
    if not re.fullmatch(
        rf"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+::{re.escape(TASK_ARCHIVE_SYNC_MODULE)}",
        destination,
    ):
        raise TaskArchiveSyncReceiverError("rsync destination must be the fixed archive module")
    source = str(argv[-2])
    if not source.endswith(os.sep):
        raise TaskArchiveSyncReceiverError("rsync source must be the task root with a trailing slash")


validate_rsync_argv = _assert_safe_rsync_argv


def _stderr_hint(value: Any) -> str:
    if isinstance(value, bytes):
        return value[:2048].decode("utf-8", "replace").lower()
    if isinstance(value, str):
        return value[:2048].lower()
    return ""


def classify_rsync_result(
    returncode: int | None,
    *,
    stderr: str | bytes | None = None,
    timed_out: bool = False,
    cancelled: bool = False,
) -> TaskArchiveSyncClassification:
    """Map rsync/SSH outcomes to stable, bounded categories."""

    hint = _stderr_hint(stderr)
    if cancelled:
        return TaskArchiveSyncClassification(
            TaskArchiveSyncCategory.cancelled, False, True, returncode, "cycle cancelled"
        )
    if timed_out or returncode in {30, 124}:
        return TaskArchiveSyncClassification(
            TaskArchiveSyncCategory.timeout, False, True, returncode, "transfer timed out"
        )
    if returncode == 0:
        return TaskArchiveSyncClassification(
            TaskArchiveSyncCategory.success, True, False, 0, "rsync completed"
        )
    if returncode == 24:
        return TaskArchiveSyncClassification(
            TaskArchiveSyncCategory.incomplete,
            False,
            True,
            24,
            "source changed during transfer; retryable incomplete cycle",
        )
    if "timed out" in hint or "timeout" in hint:
        category = TaskArchiveSyncCategory.timeout
        detail = "transfer timed out"
    elif (
        "host key" in hint
        or "host identification has changed" in hint
        or "known_hosts" in hint
        or "offending" in hint
    ):
        category = TaskArchiveSyncCategory.host_key
        detail = "SSH host-key verification failed"
    elif returncode == 255 and _contains_ssh_authentication_evidence(hint):
        category = TaskArchiveSyncCategory.ssh_auth
        detail = "SSH authentication failed"
    elif _contains_transport_evidence(hint):
        category = TaskArchiveSyncCategory.transport
        detail = "SSH or rsync transport failed"
    elif "no space" in hint or "enospc" in hint or "disk full" in hint:
        category = TaskArchiveSyncCategory.remote_space
        detail = "receiver storage is full"
    elif (
        "forbidden" in hint
        or "not permitted" in hint
        or "refus" in hint
        or "delete" in hint
    ):
        category = TaskArchiveSyncCategory.receiver_policy
        detail = "receiver policy rejected the transfer"
    elif "permission" in hint or returncode == 23:
        category = TaskArchiveSyncCategory.permission
        detail = "source or receiver permission failed"
    elif returncode == 255:
        # SSH uses 255 for DNS failures, connection refusal, and host routing
        # errors as well as authentication.  Without explicit auth evidence,
        # classify it as transport so operators do not chase the wrong secret.
        category = TaskArchiveSyncCategory.transport
        detail = "SSH connection failed"
    elif returncode in {10, 11, 12}:
        category = TaskArchiveSyncCategory.transport
        detail = "rsync transport failed"
    else:
        category = TaskArchiveSyncCategory.unknown
        detail = "rsync failed with an unclassified result"
    return TaskArchiveSyncClassification(category, False, True, returncode, detail)


def _contains_ssh_authentication_evidence(hint: str) -> bool:
    return any(
        marker in hint
        for marker in (
            "permission denied (",
            "publickey",
            "publickey authentication",
            "no supported authentication methods",
            "authentication that can continue",
            "authentication failed",
            "failed to authenticate",
            "sign_and_send_pubkey",
            "too many authentication failures",
        )
    )


def _contains_transport_evidence(hint: str) -> bool:
    return any(
        marker in hint
        for marker in (
            "connection refused",
            "could not resolve hostname",
            "name or service not known",
            "temporary failure in name resolution",
            "no route to host",
            "connection closed",
            "connection unexpectedly closed",
            "did not see server greeting",
            "connection timed out",
        )
    )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class TaskArchiveSynchronizer:
    """Execute one non-overlapping raw archive transfer per ``run_once`` call."""

    def __init__(
        self,
        config: TaskArchiveSyncConfig,
        store: Any,
        *,
        runner: Callable[..., Any] | None = None,
        subprocess_runner: Callable[..., Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        cancellation: Callable[[], bool] | None = None,
        cancel_event: Any | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self._owns_process_group = runner is None and subprocess_runner is None
        self._runner = runner or subprocess_runner or self._start_process
        self._clock = clock or _now_utc
        self._monotonic = monotonic or time.monotonic
        self._cancellation = cancellation or (
            (lambda: bool(cancel_event.is_set())) if cancel_event is not None else None
        )
        setter = getattr(store, "set_task_archive_sync_enabled", None)
        if setter is not None:
            setter(config.enabled)

    def build_ssh_argv(self) -> list[str]:
        return build_ssh_argv(self.config)

    def build_rsync_argv(self) -> list[str]:
        return build_rsync_argv(self.config)

    def _cancelled(self) -> bool:
        return self._cancellation is not None and bool(self._cancellation())

    @staticmethod
    def _start_process(
        argv: list[str], *, env: dict[str, str], shell: bool, **_: Any
    ) -> Any:
        return subprocess.Popen(  # nosec B603 - argv is fixed and shell is disabled
            argv,
            env=env,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    @staticmethod
    def _is_process_handle(process_result: Any) -> bool:
        return all(
            callable(getattr(process_result, name, None))
            for name in ("communicate", "poll", "terminate", "kill")
        )

    def _signal_process(self, process: Any, process_signal: signal.Signals) -> None:
        if self._owns_process_group:
            pid = getattr(process, "pid", None)
            if isinstance(pid, int):
                try:
                    os.killpg(pid, process_signal)
                    return
                except ProcessLookupError:
                    return
                except OSError:
                    pass
        method = process.terminate if process_signal == signal.SIGTERM else process.kill
        try:
            method()
        except (OSError, ProcessLookupError):
            pass

    def _stop_process(self, process: Any) -> None:
        try:
            if process.poll() is not None:
                return
        except BaseException:
            pass
        try:
            self._signal_process(process, signal.SIGTERM)
        except BaseException:
            pass
        try:
            process.communicate(timeout=_PROCESS_STOP_GRACE_SECONDS)
        except BaseException:
            pass
        try:
            if process.poll() is not None:
                return
        except BaseException:
            pass
        try:
            self._signal_process(process, signal.SIGKILL)
        except BaseException:
            pass
        try:
            process.communicate(timeout=_PROCESS_STOP_GRACE_SECONDS)
        except BaseException:
            pass

    def _wait_for_process(self, process: Any, argv: list[str]) -> Any:
        deadline = self._monotonic() + self.config.transfer_timeout_seconds
        try:
            while True:
                if self._cancelled():
                    raise TaskArchiveSyncCancelled
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(
                        argv, self.config.transfer_timeout_seconds
                    )
                try:
                    stdout, stderr = process.communicate(
                        timeout=min(_PROCESS_WAIT_SLICE_SECONDS, remaining)
                    )
                except subprocess.TimeoutExpired:
                    continue
                if self._cancelled():
                    raise TaskArchiveSyncCancelled
                return subprocess.CompletedProcess(
                    argv,
                    getattr(process, "returncode", None),
                    stdout,
                    stderr,
                )
        except BaseException:
            self._stop_process(process)
            raise

    def _invoke_runner(self, argv: list[str]) -> Any:
        kwargs: dict[str, Any] = {
            "timeout": self.config.transfer_timeout_seconds,
            "env": {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
            "check": False,
            "capture_output": True,
            "shell": False,
        }
        try:
            signature = inspect.signature(self._runner)
        except (TypeError, ValueError):
            signature = None
        if signature is not None and not any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            kwargs = {
                name: value
                for name, value in kwargs.items()
                if name in signature.parameters
            }
        process_result = self._runner(argv, **kwargs)
        if self._is_process_handle(process_result):
            return self._wait_for_process(process_result, argv)
        if self._cancelled():
            raise TaskArchiveSyncCancelled
        return process_result

    @staticmethod
    def _returncode(process_result: Any) -> int | None:
        if isinstance(process_result, int):
            return process_result
        value = getattr(process_result, "returncode", None)
        return value if isinstance(value, int) else None

    @staticmethod
    def _stderr(process_result: Any) -> str | bytes | None:
        return getattr(process_result, "stderr", None)

    def run_once(self) -> TaskArchiveSyncResult:
        if not self.config.enabled:
            return TaskArchiveSyncResult(
                None,
                "disabled",
                TaskArchiveSyncCategory.disabled,
                False,
                False,
                safe_detail="synchronizer disabled",
            )
        cycle_id = f"archive-sync-{uuid4().hex}"
        validate_cycle_id(cycle_id)
        started = self._clock()
        claim = getattr(self.store, "claim_task_archive_sync_cycle")
        try:
            claimed = claim(cycle_id, started_at=started, require_enabled=True)
        except Exception:
            return TaskArchiveSyncResult(
                cycle_id,
                "failure",
                TaskArchiveSyncCategory.unknown,
                False,
                True,
                safe_detail="health claim failed",
            )
        if not claimed:
            return TaskArchiveSyncResult(
                None,
                "busy",
                TaskArchiveSyncCategory.busy,
                False,
                True,
                safe_detail="another cycle is active",
            )
        started_tick = self._monotonic()
        classification: TaskArchiveSyncClassification
        interruption: BaseException | None = None
        try:
            if self._cancelled():
                raise TaskArchiveSyncCancelled
            validate_source_tree(self.config.tasks_dir)
            argv = self.build_rsync_argv()
            if self._cancelled():
                raise TaskArchiveSyncCancelled
            process_result = self._invoke_runner(argv)
            classification = classify_rsync_result(
                self._returncode(process_result), stderr=self._stderr(process_result)
            )
        except subprocess.TimeoutExpired:
            classification = classify_rsync_result(None, timed_out=True)
        except TimeoutError:
            classification = classify_rsync_result(None, timed_out=True)
        except TaskArchiveSyncCancelled:
            classification = classify_rsync_result(None, cancelled=True)
        except TaskArchiveSyncSourceError:
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.source_invariant,
                False,
                False,
                None,
                "source tree contains unsupported filesystem state",
            )
        except PermissionError:
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.permission,
                False,
                True,
                None,
                "source or receiver permission failed",
            )
        except FileNotFoundError:
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.transport,
                False,
                True,
                None,
                "rsync or SSH executable is unavailable",
            )
        except TaskArchiveSyncReceiverError:
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.receiver_policy,
                False,
                False,
                None,
                "transfer violates the receiver policy",
            )
        except (OSError, ValueError, RuntimeError):
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.unknown,
                False,
                True,
                None,
                "synchronizer failed before transfer completion",
            )
        except Exception:
            # Keep the module boundary safe even for an injected subprocess
            # implementation that raises an unexpected exception.
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.unknown,
                False,
                True,
                None,
                "synchronizer failed before transfer completion",
            )
        except (KeyboardInterrupt, SystemExit) as exc:
            interruption = exc
            classification = TaskArchiveSyncClassification(
                TaskArchiveSyncCategory.interrupted,
                False,
                True,
                None,
                "cycle interrupted before completion",
            )
        except BaseException:
            # asyncio.CancelledError is a BaseException on supported Python
            # versions; contain it as a deterministic cancellation outcome.
            classification = classify_rsync_result(None, cancelled=True)
        duration = min(max(0.0, self._monotonic() - started_tick), 86400.0)
        persisted = False
        try:
            if classification.success:
                persisted = bool(self.store.finish_task_archive_sync_success(
                    cycle_id,
                    finished_at=self._clock(),
                    duration_seconds=duration,
                    exit_code=classification.exit_code or 0,
                    safe_detail=classification.safe_detail,
                ))
            else:
                persisted = bool(self.store.finish_task_archive_sync_failure(
                    cycle_id,
                    category=str(classification.category),
                    exit_code=classification.exit_code,
                    safe_detail=classification.safe_detail,
                    finished_at=self._clock(),
                    duration_seconds=duration,
                ))
        except Exception:
            # A health persistence error must not mutate or fail a task run.
            pass
        if not persisted:
            try:
                self.store.reconcile_interrupted_task_archive_sync(
                    finished_at=self._clock(),
                    safe_detail="cycle health completion was unavailable",
                )
            except Exception:
                pass
        health: TaskArchiveSyncHealth | None = None
        getter = getattr(self.store, "get_task_archive_sync_health", None)
        if getter is not None:
            try:
                health = getter()
            except Exception:
                health = None
        if interruption is not None:
            raise interruption
        status = "success" if classification.success else (
            "incomplete" if classification.incomplete else "failure"
        )
        if classification.category == TaskArchiveSyncCategory.cancelled:
            status = "cancelled"
        return TaskArchiveSyncResult(
            cycle_id,
            status,
            str(classification.category),
            classification.success,
            classification.retryable,
            classification.exit_code,
            duration,
            bounded_safe_detail(classification.safe_detail),
            health,
        )

    run = run_once


# Compatibility aliases for callers that use the shorter operation name.
TaskArchiveSync = TaskArchiveSynchronizer
TaskArchiveSyncConfig = TaskArchiveSyncConfig
TaskArchiveSyncFailureCategory = TaskArchiveSyncCategory
build_rsync_args = build_rsync_argv
build_ssh_args = build_ssh_argv
forced_receiver_command = validate_forced_receiver_command


__all__ = [
    "ForcedReceiverPolicy",
    "FakeTaskArchiveReceiver",
    "ReceiverHarness",
    "TaskArchiveSync",
    "TaskArchiveSyncCategory",
    "TaskArchiveSyncCancelled",
    "TaskArchiveSyncClassification",
    "TaskArchiveSyncConfig",
    "TaskArchiveSyncFailureCategory",
    "TaskArchiveSyncHealth",
    "TaskArchiveSyncReceiverError",
    "TaskArchiveSyncResult",
    "TaskArchiveSyncSourceError",
    "TaskArchiveSynchronizer",
    "build_forced_receiver_authorized_key",
    "build_fixed_receiver_config",
    "build_receiver_rsyncd_config",
    "build_rsync_argv",
    "build_rsync_args",
    "build_ssh_argv",
    "build_ssh_args",
    "classify_rsync_result",
    "forced_receiver_command",
    "validate_forced_receiver_command",
    "validate_rsync_argv",
    "validate_receiver_relative_path",
    "validate_receiver_upload",
    "validate_source_tree",
]

"""One restricted rsync operation for Steward's raw dataset.

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

from .dataset_sync_config import (
    DATASET_SYNC_CONFIG_PATH,
    DATASET_SYNC_MODULE,
    DatasetSyncConfig,
    DatasetSyncHealth,
    bounded_safe_detail,
    validate_cycle_id,
)


class DatasetSyncCategory(StrEnum):
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


class DatasetSyncCancelled(RuntimeError):
    """Raised by an injected runner or cancellation hook to stop a cycle."""


class DatasetSyncSourceError(RuntimeError):
    """The source tree contains unsupported or unsafe filesystem state."""


class DatasetSyncReceiverError(ValueError):
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


_PUBLIC_ROOTS = frozenset({"tasks", "control-loop"})
_FORBIDDEN_SHORT_RSYNC_FLAGS = frozenset("aAlLDogpHKRX")


def _receiver_root(dataset_root: Path) -> Path:
    root = Path(dataset_root).expanduser()
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts):
        raise DatasetSyncReceiverError("receiver root must be an absolute clean path")
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise DatasetSyncReceiverError("receiver root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise DatasetSyncReceiverError("receiver root must be an absolute directory")
    if stat.S_ISLNK(metadata.st_mode):
        raise DatasetSyncReceiverError("receiver root must not be a symlink")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise DatasetSyncReceiverError("receiver dataset parent must not be group- or world-writable")
    for name in _PUBLIC_ROOTS:
        child = root / name
        try:
            child_metadata = child.lstat()
        except OSError as exc:
            raise DatasetSyncReceiverError("receiver public roots are unavailable") from exc
        if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(child_metadata.st_mode):
            raise DatasetSyncReceiverError("receiver public roots must be existing directories")
    for name in ("cache", "release", "releases", "service", "ssh"):
        sibling = root / name
        if not sibling.exists():
            continue
        sibling_metadata = sibling.lstat()
        if stat.S_ISLNK(sibling_metadata.st_mode) or not stat.S_ISDIR(sibling_metadata.st_mode):
            raise DatasetSyncReceiverError("receiver private siblings must be directories")
        if stat.S_IMODE(sibling_metadata.st_mode) & 0o022:
            raise DatasetSyncReceiverError("receiver private siblings must not be group- or world-writable")
    return root


def build_receiver_rsyncd_config(
    dataset_root: Path,
    *,
    module: str = DATASET_SYNC_MODULE,
) -> str:
    """Return the fixed write-only receiver configuration.

    The resulting text is intended for the operator-managed receiver image or
    the fake protocol harness.  It contains no source data or credentials.
    """

    if module != DATASET_SYNC_MODULE:
        raise DatasetSyncReceiverError("receiver module is fixed")
    root = _receiver_root(dataset_root)
    return (
        "use chroot = no\n"
        "read only = no\n"
        "write only = yes\n"
        "list = no\n"
        "reverse lookup = no\n"
        f"refuse options = {_RECEIVER_REFUSED_OPTIONS}\n"
        f"exclude = {_RECEIVER_HIDDEN_EXCLUDES}\n"
        f"[{DATASET_SYNC_MODULE}]\n"
        f"path = {root}\n"
        "read only = no\n"
        "write only = yes\n"
        "list = no\n"
        f"refuse options = {_RECEIVER_REFUSED_OPTIONS}\n"
        f'pre-xfer exec = /usr/bin/test "$RSYNC_REQUEST" = "{DATASET_SYNC_MODULE}/"\n'
        f"exclude = {_RECEIVER_HIDDEN_EXCLUDES}\n"
    )


build_fixed_receiver_config = build_receiver_rsyncd_config


def validate_receiver_upload(
    relative_path: str,
    dataset_root: Path | None = None,
    *,
    options: Sequence[str] = (),
    module: str | None = None,
) -> Path:
    """Validate a dataset-relative upload for the fake receiver boundary.

    The accepted top-level names are exactly ``tasks`` and ``control-loop``.
    A two-positional-argument call using the fixed module label remains
    accepted by the harness for tests that exercise daemon framing; production
    argv never uses module syntax.
    """

    if module is not None:
        if module != DATASET_SYNC_MODULE:
            raise DatasetSyncReceiverError("receiver module is not allowed")
        if relative_path == DATASET_SYNC_MODULE and dataset_root is not None:
            relative_path, dataset_root = str(dataset_root), None
    if relative_path == DATASET_SYNC_MODULE and dataset_root is not None:
        # Legacy daemon framing passes the module then the request path. It is
        # still checked against the fixed module, but never exposes a path.
        relative_path, dataset_root = str(dataset_root), None
    if relative_path not in {"", ".", "./"}:
        validate_receiver_relative_path(relative_path, dataset_root or Path("/fixed/steward"))
    forbidden = {
        "archive",
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
        "a",
        "l",
        "L",
        "D",
        "o",
        "g",
        "p",
        "H",
        "K",
        "X",
    }
    for option in options:
        raw = str(option)
        token = raw.lstrip("-").split("=", 1)[0]
        if token in forbidden or (
            raw.startswith("-")
            and not raw.startswith("--")
            and any(flag in _FORBIDDEN_SHORT_RSYNC_FLAGS for flag in token)
        ):
            raise DatasetSyncReceiverError("receiver option is refused")
    return Path(dataset_root) if dataset_root is not None else Path(".")


@dataclass(frozen=True, slots=True)
class FakeDatasetReceiver:
    """Policy harness for tests that exercise real rsync daemon framing.

    Tests may launch ``rsync --daemon --config=<config>`` using
    :meth:`config_text`; this object only validates the SSH forced command and
    the fixed module root, leaving protocol framing to the installed rsync.
    """

    dataset_root: Path
    module: str = DATASET_SYNC_MODULE
    config_path: str = DATASET_SYNC_CONFIG_PATH

    def __post_init__(self) -> None:
        _receiver_root(self.dataset_root)
        if self.module != DATASET_SYNC_MODULE:
            raise ValueError("receiver module is fixed")
        config_path = str(self.config_path)
        if config_path != DATASET_SYNC_CONFIG_PATH:
            raise ValueError("receiver config path is fixed")
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
        return build_receiver_rsyncd_config(self.dataset_root, module=self.module)

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
        path_or_module: str,
        relative_path: str = ".",
        *,
        options: Sequence[str] = (),
    ) -> Path:
        # Accept both ``accept_upload(path)`` and the old framing shape
        # ``accept_upload(module, path)`` without widening production policy.
        selected = relative_path if path_or_module == self.module else path_or_module
        validate_receiver_upload(selected, self.dataset_root, options=options)
        return Path(self.dataset_root)


ReceiverHarness = FakeDatasetReceiver


@dataclass(frozen=True, slots=True)
class DatasetSyncClassification:
    category: str
    success: bool
    retryable: bool
    exit_code: int | None
    safe_detail: str

    @property
    def incomplete(self) -> bool:
        return self.category == DatasetSyncCategory.incomplete


@dataclass(frozen=True, slots=True)
class DatasetSyncResult:
    cycle_id: str | None
    status: str
    category: str
    success: bool
    retryable: bool
    exit_code: int | None = None
    duration_seconds: float | None = None
    safe_detail: str | None = None
    health: DatasetSyncHealth | None = None

    @property
    def completed(self) -> bool:
        return self.status in {"success", "incomplete", "failure", "cancelled"}

    @property
    def incomplete(self) -> bool:
        return self.category == DatasetSyncCategory.incomplete

    @property
    def busy(self) -> bool:
        return self.category == DatasetSyncCategory.busy

    @property
    def exit_category(self) -> str:
        return self.category

    @property
    def failure_category(self) -> str:
        return self.category


@dataclass(frozen=True, slots=True)
class ForcedReceiverPolicy:
    """Validation rules represented by the fixed daemon-over-SSH key."""

    dataset_root: Path
    rsync_path: str = "/usr/bin/rsync"
    config_path: str = DATASET_SYNC_CONFIG_PATH
    module: str = DATASET_SYNC_MODULE

    def __post_init__(self) -> None:
        root = Path(self.dataset_root).expanduser()
        if (
            not root.is_absolute()
            or not root.name
            or any(part in {".", ".."} for part in root.parts)
        ):
            raise ValueError("dataset_root must be an absolute path")
        if not self.rsync_path.startswith("/") or any(
            character in self.rsync_path for character in ('"', "'", "\n", "\x00")
        ):
            raise ValueError("rsync_path must be an absolute executable path")
        if self.rsync_path != "/usr/bin/rsync":
            raise ValueError("rsync_path is fixed to the locked rsync executable")
        if self.config_path != DATASET_SYNC_CONFIG_PATH:
            raise ValueError("config_path is fixed to the receiver daemon config")
        if self.module != DATASET_SYNC_MODULE:
            raise ValueError("module is fixed to the dataset module")
        object.__setattr__(self, "dataset_root", root)

    @property
    def forced_command(self) -> str:
        return (
            f"{self.rsync_path} --server --daemon "
            f"--config={self.config_path} ."
        )

    def authorized_key_line(self, public_key: str) -> str:
        return build_forced_receiver_authorized_key(
            public_key,
            self.dataset_root,
            rsync_path=self.rsync_path,
            config_path=self.config_path,
            module=self.module,
        )

    def validate_command(self, original_command: str) -> tuple[str, ...]:
        return validate_forced_receiver_command(original_command)

    def validate_relative_path(self, relative_path: str) -> Path:
        return validate_receiver_relative_path(relative_path, self.dataset_root)


def build_forced_receiver_authorized_key(
    public_key: str,
    dataset_root: Path,
    *,
    rsync_path: str = "/usr/bin/rsync",
    config_path: str = DATASET_SYNC_CONFIG_PATH,
    module: str = DATASET_SYNC_MODULE,
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
        Path(dataset_root),
        rsync_path=rsync_path,
        config_path=config_path,
        module=module,
    )
    return f'restrict,command="{policy.forced_command}" {key}'


def validate_receiver_relative_path(relative_path: str, dataset_root: Path) -> Path:
    """Resolve a receiver-relative path while rejecting escape and absolutes."""

    if not isinstance(relative_path, str) or not relative_path:
        raise DatasetSyncReceiverError("receiver path is required")
    if "\x00" in relative_path or "\\" in relative_path:
        raise DatasetSyncReceiverError("receiver path contains unsupported bytes")
    candidate = Path(relative_path)
    if candidate.is_absolute() or relative_path.startswith("~"):
        raise DatasetSyncReceiverError("receiver path must be relative")
    parts = candidate.parts
    if not parts or parts[0] not in _PUBLIC_ROOTS:
        raise DatasetSyncReceiverError("receiver upload must use tasks or control-loop")
    if any(part in {"", ".", ".."} or _is_hidden(part) for part in parts):
        raise DatasetSyncReceiverError("receiver upload contains a hidden or unsafe entry")
    root = Path(dataset_root).resolve()
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise DatasetSyncReceiverError("receiver path escapes fixed root") from exc
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
    config_path: str = DATASET_SYNC_CONFIG_PATH,
) -> tuple[str, ...]:
    """Validate the exact fixed daemon command sent to the SSH receiver."""

    if rsync_path != "/usr/bin/rsync" or config_path != DATASET_SYNC_CONFIG_PATH:
        raise DatasetSyncReceiverError("receiver command policy is fixed")
    if not isinstance(original_command, str) or not original_command.strip():
        raise DatasetSyncReceiverError("empty forced receiver command")
    if any(character in original_command for character in ("\x00", "\n", "\r")):
        raise DatasetSyncReceiverError("receiver command contains control bytes")
    try:
        tokens = tuple(shlex.split(original_command, posix=True))
    except ValueError as exc:
        raise DatasetSyncReceiverError("receiver command is not shell-safe") from exc
    expected = (
        rsync_path,
        "--server",
        "--daemon",
        f"--config={config_path}",
        ".",
    )
    if tokens != expected:
        raise DatasetSyncReceiverError("receiver command is not the fixed daemon invocation")
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
        raise DatasetSyncSourceError("source dataset root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise DatasetSyncSourceError("source dataset root is not a directory")


def validate_dataset_source(config: DatasetSyncConfig) -> None:
    """Revalidate both roots and the shared immutable epoch immediately preflight."""

    if config.tasks_dir is None or config.control_loop_dir is None:
        raise DatasetSyncSourceError("dataset roots are not configured")
    try:
        from .dataset_sync_config import validate_dataset_roots

        validate_dataset_roots(config.tasks_dir, config.control_loop_dir)
    except (OSError, ValueError) as exc:
        raise DatasetSyncSourceError("dataset roots or shared epoch are invalid") from exc
    validate_source_tree(config.tasks_dir)
    validate_source_tree(config.control_loop_dir)


def build_ssh_argv(config: DatasetSyncConfig) -> list[str]:
    """Build strict SSH transport options for the forced receiver."""

    timeout = str(max(1, math.ceil(config.connect_timeout_seconds)))
    return [
        config.ssh_bin,
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


def build_rsync_argv(config: DatasetSyncConfig) -> list[str]:
    """Build one recursive transfer with exactly two explicit source roots."""

    if config.tasks_dir is None or config.control_loop_dir is None:
        raise DatasetSyncSourceError("dataset roots are not configured")
    sources = (str(config.tasks_dir), str(config.control_loop_dir))
    if any(source.endswith(os.sep) for source in sources):
        raise DatasetSyncSourceError("dataset sources must not have trailing slashes")
    # ``::module`` is intentional: it selects the fixed rsync daemon module
    # behind the SSH forced command. A single-colon destination would ask the
    # forced daemon to serve a shell path and is rejected by the receiver.
    destination = (
        f"{config.remote_user}@{config.remote_host}::{DATASET_SYNC_MODULE}"
    )
    ssh_command = shlex.join(build_ssh_argv(config))
    argv = [
        config.rsync_bin,
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
        *sources,
        destination,
    ]
    _assert_safe_rsync_argv(argv)
    return argv


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
            raise DatasetSyncReceiverError("rsync argv contains a forbidden option")
        if raw.startswith("-") and not raw.startswith("--"):
            if any(flag in raw[1:] for flag in _FORBIDDEN_SHORT_RSYNC_FLAGS):
                raise DatasetSyncReceiverError(
                    "rsync argv contains a forbidden option"
                )
        if lowered.startswith("--remove") or lowered.startswith("--delete"):
            raise DatasetSyncReceiverError("rsync argv contains a deletion option")
    if not argv or Path(str(argv[0])).name != "rsync":
        raise DatasetSyncReceiverError("argv must invoke rsync directly")
    required_options = {
        "--recursive",
        "--times",
        "--protect-args",
        "--modify-window=-1",
        "--exclude=.*",
        "--exclude=*/.*",
        "--exclude=~*",
    }
    if not required_options.issubset({str(token) for token in argv}):
        raise DatasetSyncReceiverError("rsync argv is missing a required restriction")
    if len(argv) < 3:
        raise DatasetSyncReceiverError("rsync argv is incomplete")
    try:
        rsh_index = list(argv).index("--rsh")
    except ValueError as exc:
        raise DatasetSyncReceiverError("rsync must use the locked SSH transport") from exc
    if len(argv) != rsh_index + 5:
        raise DatasetSyncReceiverError("rsync must contain exactly two source roots")
    try:
        rsh_tokens = tuple(shlex.split(str(argv[rsh_index + 1]), posix=True))
    except ValueError as exc:
        raise DatasetSyncReceiverError("rsync SSH transport is not shell-safe") from exc
    if not rsh_tokens or Path(rsh_tokens[0]).name != "ssh":
        raise DatasetSyncReceiverError("rsync must use the locked SSH executable")
    required_rsh = {
        "-T",
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
    }
    if not required_rsh.issubset(set(rsh_tokens)):
        raise DatasetSyncReceiverError("rsync SSH transport is not restricted")
    if "-i" not in rsh_tokens or "-p" not in rsh_tokens:
        raise DatasetSyncReceiverError("rsync SSH transport lacks fixed credentials or port")
    if not any(token.startswith("ConnectTimeout=") for token in rsh_tokens):
        raise DatasetSyncReceiverError("rsync SSH transport lacks a connect timeout")
    if not any(token.startswith("UserKnownHostsFile=") for token in rsh_tokens):
        raise DatasetSyncReceiverError("rsync SSH transport lacks fixed host keys")
    if any(
        token in {"--rsync-path", "-e", "--command", "--remote-option"}
        or token.startswith("--rsync-path=")
        for token in rsh_tokens
    ):
        raise DatasetSyncReceiverError("rsync SSH transport contains a selectable command")
    destination = str(argv[-1])
    if not re.fullmatch(
        rf"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+::{re.escape(DATASET_SYNC_MODULE)}",
        destination,
    ):
        raise DatasetSyncReceiverError(
            "rsync destination must be the fixed steward-dataset module"
        )
    sources = tuple(str(value) for value in argv[-3:-1])
    if len(sources) != 2 or any(
        not Path(source).is_absolute()
        or any(part in {".", ".."} for part in Path(source).parts)
        for source in sources
    ):
        raise DatasetSyncReceiverError("rsync must receive two absolute dataset roots")
    if {Path(source).name for source in sources} != _PUBLIC_ROOTS:
        raise DatasetSyncReceiverError("rsync sources must be tasks and control-loop")
    if any(source.endswith(os.sep) for source in sources):
        raise DatasetSyncReceiverError("rsync sources must not have trailing slashes")
    if Path(sources[0]).parent != Path(sources[1]).parent:
        raise DatasetSyncReceiverError("rsync sources must be sibling roots")


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
) -> DatasetSyncClassification:
    """Map rsync/SSH outcomes to stable, bounded categories."""

    hint = _stderr_hint(stderr)
    if cancelled:
        return DatasetSyncClassification(
            DatasetSyncCategory.cancelled, False, True, returncode, "cycle cancelled"
        )
    if timed_out or returncode in {30, 124}:
        return DatasetSyncClassification(
            DatasetSyncCategory.timeout, False, True, returncode, "transfer timed out"
        )
    if returncode == 0:
        return DatasetSyncClassification(
            DatasetSyncCategory.success, True, False, 0, "rsync completed"
        )
    if returncode == 24:
        return DatasetSyncClassification(
            DatasetSyncCategory.incomplete,
            False,
            True,
            24,
            "source changed during transfer; retryable incomplete cycle",
        )
    if "timed out" in hint or "timeout" in hint:
        category = DatasetSyncCategory.timeout
        detail = "transfer timed out"
    elif (
        "host key" in hint
        or "host identification has changed" in hint
        or "known_hosts" in hint
        or "offending" in hint
    ):
        category = DatasetSyncCategory.host_key
        detail = "SSH host-key verification failed"
    elif returncode == 255 and _contains_ssh_authentication_evidence(hint):
        category = DatasetSyncCategory.ssh_auth
        detail = "SSH authentication failed"
    elif _contains_transport_evidence(hint):
        category = DatasetSyncCategory.transport
        detail = "SSH or rsync transport failed"
    elif "no space" in hint or "enospc" in hint or "disk full" in hint:
        category = DatasetSyncCategory.remote_space
        detail = "receiver storage is full"
    elif (
        "forbidden" in hint
        or "not permitted" in hint
        or "refus" in hint
        or "delete" in hint
    ):
        category = DatasetSyncCategory.receiver_policy
        detail = "receiver policy rejected the transfer"
    elif "permission" in hint or returncode == 23:
        category = DatasetSyncCategory.permission
        detail = "source or receiver permission failed"
    elif returncode == 255:
        # SSH uses 255 for DNS failures, connection refusal, and host routing
        # errors as well as authentication.  Without explicit auth evidence,
        # classify it as transport so operators do not chase the wrong secret.
        category = DatasetSyncCategory.transport
        detail = "SSH connection failed"
    elif returncode in {10, 11, 12}:
        category = DatasetSyncCategory.transport
        detail = "rsync transport failed"
    else:
        category = DatasetSyncCategory.unknown
        detail = "rsync failed with an unclassified result"
    return DatasetSyncClassification(category, False, True, returncode, detail)


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


class StewardDatasetSynchronizer:
    """Execute one non-overlapping raw archive transfer per ``run_once`` call."""

    def __init__(
        self,
        config: DatasetSyncConfig,
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
        setter = getattr(store, "set_dataset_sync_enabled", None)
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
                    raise DatasetSyncCancelled
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
                    raise DatasetSyncCancelled
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
            raise DatasetSyncCancelled
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

    def run_once(self) -> DatasetSyncResult:
        if not self.config.enabled:
            return DatasetSyncResult(
                None,
                "disabled",
                DatasetSyncCategory.disabled,
                False,
                False,
                safe_detail="synchronizer disabled",
            )
        cycle_id = f"dataset-sync-{uuid4().hex}"
        validate_cycle_id(cycle_id)
        started = self._clock()
        claim = getattr(self.store, "claim_dataset_sync_cycle")
        try:
            claimed = claim(cycle_id, started_at=started, require_enabled=True)
        except Exception:
            return DatasetSyncResult(
                cycle_id,
                "failure",
                DatasetSyncCategory.unknown,
                False,
                True,
                safe_detail="health claim failed",
            )
        if not claimed:
            return DatasetSyncResult(
                None,
                "busy",
                DatasetSyncCategory.busy,
                False,
                True,
                safe_detail="another cycle is active",
            )
        started_tick = self._monotonic()
        classification: DatasetSyncClassification
        interruption: BaseException | None = None
        try:
            if self._cancelled():
                raise DatasetSyncCancelled
            validate_dataset_source(self.config)
            argv = self.build_rsync_argv()
            if self._cancelled():
                raise DatasetSyncCancelled
            process_result = self._invoke_runner(argv)
            classification = classify_rsync_result(
                self._returncode(process_result), stderr=self._stderr(process_result)
            )
        except subprocess.TimeoutExpired:
            classification = classify_rsync_result(None, timed_out=True)
        except TimeoutError:
            classification = classify_rsync_result(None, timed_out=True)
        except DatasetSyncCancelled:
            classification = classify_rsync_result(None, cancelled=True)
        except DatasetSyncSourceError:
            classification = DatasetSyncClassification(
                DatasetSyncCategory.source_invariant,
                False,
                False,
                None,
                "source tree contains unsupported filesystem state",
            )
        except PermissionError:
            classification = DatasetSyncClassification(
                DatasetSyncCategory.permission,
                False,
                True,
                None,
                "source or receiver permission failed",
            )
        except FileNotFoundError:
            classification = DatasetSyncClassification(
                DatasetSyncCategory.transport,
                False,
                True,
                None,
                "rsync or SSH executable is unavailable",
            )
        except DatasetSyncReceiverError:
            classification = DatasetSyncClassification(
                DatasetSyncCategory.receiver_policy,
                False,
                False,
                None,
                "transfer violates the receiver policy",
            )
        except (OSError, ValueError, RuntimeError):
            classification = DatasetSyncClassification(
                DatasetSyncCategory.unknown,
                False,
                True,
                None,
                "synchronizer failed before transfer completion",
            )
        except Exception:
            # Keep the module boundary safe even for an injected subprocess
            # implementation that raises an unexpected exception.
            classification = DatasetSyncClassification(
                DatasetSyncCategory.unknown,
                False,
                True,
                None,
                "synchronizer failed before transfer completion",
            )
        except (KeyboardInterrupt, SystemExit) as exc:
            interruption = exc
            classification = DatasetSyncClassification(
                DatasetSyncCategory.interrupted,
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
                persisted = bool(self.store.finish_dataset_sync_success(
                    cycle_id,
                    finished_at=self._clock(),
                    duration_seconds=duration,
                    exit_code=classification.exit_code or 0,
                    safe_detail=classification.safe_detail,
                ))
            else:
                persisted = bool(self.store.finish_dataset_sync_failure(
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
                self.store.reconcile_interrupted_dataset_sync(
                    finished_at=self._clock(),
                    safe_detail="cycle health completion was unavailable",
                )
            except Exception:
                pass
        health: DatasetSyncHealth | None = None
        getter = getattr(self.store, "get_dataset_sync_health", None)
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
        if classification.category == DatasetSyncCategory.cancelled:
            status = "cancelled"
        return DatasetSyncResult(
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


# Descriptive aliases for callers that use the shorter operation name.
DatasetSync = StewardDatasetSynchronizer
DatasetSynchronizer = StewardDatasetSynchronizer
FakeStewardDatasetReceiver = FakeDatasetReceiver
DatasetSyncConfig = DatasetSyncConfig
DatasetSyncFailureCategory = DatasetSyncCategory
build_rsync_args = build_rsync_argv
build_ssh_args = build_ssh_argv
forced_receiver_command = validate_forced_receiver_command


__all__ = [
    "ForcedReceiverPolicy",
    "FakeDatasetReceiver",
    "FakeStewardDatasetReceiver",
    "ReceiverHarness",
    "DatasetSync",
    "DatasetSyncCategory",
    "DatasetSyncCancelled",
    "DatasetSyncClassification",
    "DatasetSyncConfig",
    "DatasetSyncFailureCategory",
    "DatasetSynchronizer",
    "DatasetSyncHealth",
    "DatasetSyncReceiverError",
    "DatasetSyncResult",
    "DatasetSyncSourceError",
    "StewardDatasetSynchronizer",
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
    "validate_dataset_source",
]

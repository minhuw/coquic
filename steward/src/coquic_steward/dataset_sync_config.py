"""Configuration and bounded operational records for raw dataset synchronisation.

This module deliberately does not read Steward's TOML configuration.  Plan 006
owns loading these values into the daemon; keeping the value object independent
also makes it possible to validate a receiver boundary before a transfer.
"""

from __future__ import annotations

import json
import math
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final


DATASET_SYNC_HEALTH_ID: Final[str] = "dataset-sync"
# The receiver is a forced SSH server process, not a selectable rsync module.
# Keep this constant as a descriptive policy label for callers that need one.
DATASET_SYNC_MODULE: Final[str] = "steward-dataset"
DATASET_SYNC_CONFIG_PATH: Final[str] = "/fixed/rsyncd.conf"
# Descriptive aliases used by operator-facing callers.
FIXED_RECEIVER_MODULE: Final[str] = DATASET_SYNC_MODULE
FIXED_RECEIVER_CONFIG_PATH: Final[str] = DATASET_SYNC_CONFIG_PATH
MAX_CYCLE_ID_LENGTH: Final[int] = 128
MAX_SAFE_DETAIL_LENGTH: Final[int] = 256

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


def _validate_regular_file(path: Path, *, label: str) -> Path:
    """Validate a credential path without following or reading its contents."""

    if path is None:
        raise ValueError(f"{label} must reference a regular file")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ValueError(f"{label} must reference a regular file") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must reference a regular non-symlink file")
    return candidate


def _validate_source_root(path: Path, *, label: str, basename: str) -> Path:
    if path is None:
        raise ValueError(f"{label} must reference an existing directory")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ValueError(f"{label} must reference an existing directory") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must reference a regular non-symlink directory")
    if candidate.name != basename:
        raise ValueError(f"{label} must have the canonical basename {basename!r}")
    resolved = candidate.resolve()
    # Public roots are siblings immediately below the Steward public parent.
    # Reject known private/runtime roots even when a caller tries to disguise
    # them with a canonical leaf name.
    forbidden_parts = {
        "steward",
        "private",
        "runtime",
        "state",
        "worktrees",
        "sessions",
        "codex-sessions",
        "transcripts",
        "cache",
        "release",
        "releases",
        "service",
        "ssh",
    }
    private_prefixes = (
        "private",
        "runtime",
        "worktree",
        "session",
        "codex",
        "transcript",
        "cache",
        "release",
        "service",
        "ssh",
    )
    if any(
        part in forbidden_parts
        or any(part.lower().startswith(prefix) for prefix in private_prefixes)
        for part in resolved.parent.parts
    ):
        raise ValueError(f"{label} is inside a private or runtime root")
    return resolved


def _read_epoch(path: Path, *, control_loop: bool) -> str:
    """Validate one immutable public epoch without retaining its contents.

    The task archive contract allows ``endedAt`` only as a null marker while
    the control-loop contract has a deliberately separate, exact schema.  A
    permissive subset check here would publish a partially migrated archive or
    a closed task epoch, so reject every extra key before a transfer claim.
    """

    epoch_path = path / "epoch.json"
    try:
        metadata = epoch_path.lstat()
    except OSError as exc:
        raise ValueError("public epoch is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("public epoch must be a regular non-symlink file")
    try:
        value = json.loads(epoch_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("public epoch is not valid JSON") from exc
    if control_loop:
        required = {
            "epochId",
            "formatVersion",
            "taskFormatVersion",
            "policy",
            "startedAt",
        }
        allowed = required
    else:
        required = {"epochId", "formatVersion", "policy", "startedAt"}
        allowed = required | {"endedAt"}
    if (
        not isinstance(value, dict)
        or set(value) != allowed
        or not required.issubset(value)
    ):
        raise ValueError("public epoch schema is incomplete")
    epoch_id = value.get("epochId")
    if not isinstance(epoch_id, str) or _SAFE_TOKEN.fullmatch(epoch_id) is None:
        raise ValueError("public epoch id is invalid")
    if value.get("formatVersion") != "1.0" or value.get("policy") != "post-steward-2.0":
        raise ValueError("public epoch schema version or policy is invalid")
    if control_loop and value.get("taskFormatVersion") != "1.0":
        raise ValueError("control-loop epoch task format is invalid")
    if not control_loop and value.get("endedAt") is not None:
        raise ValueError("task epoch must remain open")
    started = value.get("startedAt")
    if not isinstance(started, str):
        raise ValueError("public epoch start timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(started.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("public epoch start timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("public epoch start timestamp has no timezone")
    return epoch_id


def validate_dataset_roots(tasks_dir: Path, control_loop_dir: Path) -> tuple[Path, Path, str]:
    """Validate the two canonical public roots and their shared epoch ID."""

    tasks = _validate_source_root(tasks_dir, label="tasks_dir", basename="tasks")
    control = _validate_source_root(
        control_loop_dir, label="control_loop_dir", basename="control-loop"
    )
    if tasks == control or tasks.parent != control.parent:
        raise ValueError("tasks_dir and control_loop_dir must be distinct sibling roots")
    task_epoch = _read_epoch(tasks, control_loop=False)
    control_epoch = _read_epoch(control, control_loop=True)
    if task_epoch != control_epoch:
        raise ValueError("public task and control-loop epochs do not match")
    return tasks, control, task_epoch


def _validate_timeout(value: float, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > 86400:
        raise ValueError(f"{label} must be between 0 and 86400 seconds")
    return result


@dataclass(frozen=True, slots=True, init=False)
class DatasetSyncConfig:
    """Fully explicit settings for one raw two-root dataset transfer.

    The receiver destination is intentionally not configurable. A forced
    receiver confines the SSH command to the fixed dataset parent, and the
    client always sends the fixed ``steward-dataset`` daemon module.
    """

    enabled: bool
    tasks_dir: Path | None
    control_loop_dir: Path | None
    remote_user: str
    remote_host: str
    remote_port: int
    identity_path: Path
    known_hosts_path: Path
    receiver_destination: str = DATASET_SYNC_MODULE
    ssh_bin: str = "ssh"
    rsync_bin: str = "rsync"
    connect_timeout_seconds: float = 10.0
    transfer_timeout_seconds: float = 300.0

    def __init__(
        self,
        enabled: bool,
        tasks_dir: Path | None = None,
        control_loop_dir: Path | None = None,
        remote_user: str | None = None,
        remote_host: str | None = None,
        remote_port: int | None = None,
        identity_path: Path | None = None,
        known_hosts_path: Path | None = None,
        receiver_destination: str | None = None,
        connect_timeout_seconds: float = 10.0,
        transfer_timeout_seconds: float = 300.0,
        *,
        source_task_root: Path | None = None,
        source_control_loop_root: Path | None = None,
        control_root: Path | None = None,
        source_root: Path | None = None,
        identity_file: Path | None = None,
        ssh_identity_path: Path | None = None,
        ssh_key_path: Path | None = None,
        known_hosts_file: Path | None = None,
        destination: str | None = None,
        ssh_bin: str = "ssh",
        rsync_bin: str = "rsync",
        whole_transfer_timeout_seconds: float | None = None,
        transfer_timeout: float | None = None,
    ) -> None:
        """Accept explicit source and credential path spellings as aliases."""

        selected_tasks = tasks_dir or source_task_root or source_root
        selected_control = control_loop_dir or source_control_loop_root or control_root
        selected_identity = identity_path or identity_file or ssh_identity_path or ssh_key_path
        selected_known_hosts = known_hosts_path or known_hosts_file
        selected_destination = receiver_destination
        if destination is not None:
            selected_destination = destination
        selected_transfer_timeout = (
            transfer_timeout_seconds
            if whole_transfer_timeout_seconds is None and transfer_timeout is None
            else (
                whole_transfer_timeout_seconds
                if whole_transfer_timeout_seconds is not None
                else transfer_timeout
            )
        )
        object.__setattr__(self, "enabled", enabled)
        object.__setattr__(self, "tasks_dir", selected_tasks)
        object.__setattr__(self, "control_loop_dir", selected_control)
        object.__setattr__(self, "remote_user", remote_user)
        object.__setattr__(self, "remote_host", remote_host)
        object.__setattr__(self, "remote_port", remote_port)
        object.__setattr__(self, "identity_path", selected_identity)
        object.__setattr__(self, "known_hosts_path", selected_known_hosts)
        if selected_destination is not None and selected_destination != DATASET_SYNC_MODULE:
            raise ValueError(
                "receiver destination is fixed to the steward-dataset module"
            )
        object.__setattr__(self, "receiver_destination", DATASET_SYNC_MODULE)
        object.__setattr__(self, "ssh_bin", ssh_bin)
        object.__setattr__(self, "rsync_bin", rsync_bin)
        object.__setattr__(self, "connect_timeout_seconds", connect_timeout_seconds)
        object.__setattr__(self, "transfer_timeout_seconds", selected_transfer_timeout)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a boolean")
        if not self.enabled:
            return
        source, control, _epoch_id = validate_dataset_roots(
            self.tasks_dir, self.control_loop_dir
        )
        object.__setattr__(self, "tasks_dir", source)
        object.__setattr__(self, "control_loop_dir", control)

        if not isinstance(self.remote_user, str) or not _SAFE_TOKEN.fullmatch(
            self.remote_user
        ):
            raise ValueError("remote_user must be a bounded SSH user token")
        if not isinstance(self.remote_host, str) or not _SAFE_HOST.fullmatch(
            self.remote_host
        ):
            raise ValueError("remote_host must be a hostname, not a path")
        if isinstance(self.remote_port, bool) or not isinstance(self.remote_port, int):
            raise ValueError("remote_port must be an integer")
        if not 1 <= self.remote_port <= 65535:
            raise ValueError("remote_port must be between 1 and 65535")
        identity = _validate_regular_file(self.identity_path, label="identity_path")
        known_hosts = _validate_regular_file(
            self.known_hosts_path, label="known_hosts_path"
        )
        for credential, label in ((identity, "identity_path"), (known_hosts, "known_hosts_path")):
            resolved = credential.resolve()
            for public_root in (source, control):
                try:
                    resolved.relative_to(public_root)
                except ValueError:
                    continue
                raise ValueError(f"{label} must remain outside public dataset roots")
        # OpenSSH rejects a private identity that is readable by another user;
        # fail before rsync can expose a less useful authentication error.
        if stat.S_IMODE(identity.stat().st_mode) & 0o077:
            raise ValueError("identity_path must not be group- or world-readable")
        object.__setattr__(self, "identity_path", identity)
        object.__setattr__(self, "known_hosts_path", known_hosts)
        object.__setattr__(
            self,
            "connect_timeout_seconds",
            _validate_timeout(self.connect_timeout_seconds, "connect_timeout_seconds"),
        )

        for value, label, executable in (
            (self.ssh_bin, "ssh_bin", "ssh"),
            (self.rsync_bin, "rsync_bin", "rsync"),
        ):
            if (
                not isinstance(value, str)
                or not value
                or any(character.isspace() or character in "\x00\r\n" for character in value)
                or Path(value).name != executable
            ):
                raise ValueError(f"{label} must identify the locked {executable} executable")
        object.__setattr__(self, "ssh_bin", str(self.ssh_bin))
        object.__setattr__(self, "rsync_bin", str(self.rsync_bin))
        object.__setattr__(
            self,
            "transfer_timeout_seconds",
            _validate_timeout(
                self.transfer_timeout_seconds, "transfer_timeout_seconds"
            ),
        )

    @property
    def source_task_root(self) -> Path:
        return self.tasks_dir

    @property
    def source_task_dir(self) -> Path:
        return self.tasks_dir
    @property
    def source_root(self) -> Path:
        return self.tasks_dir

    @property
    def source_control_loop_root(self) -> Path:
        return self.control_loop_dir

    @property
    def identity_file(self) -> Path:
        return self.identity_path

    @property
    def ssh_key_path(self) -> Path:
        return self.identity_path

    @property
    def ssh_identity_path(self) -> Path:
        return self.identity_path

    @property
    def known_hosts_file(self) -> Path:
        return self.known_hosts_path

    @property
    def destination(self) -> str:
        return self.receiver_destination

    @property
    def whole_transfer_timeout_seconds(self) -> float:
        return self.transfer_timeout_seconds


@dataclass(frozen=True, slots=True)
class DatasetSyncHealth:
    """Operational health only; no archive, path, or subprocess output fields."""

    enabled: bool = False
    active_cycle_id: str | None = None
    last_started_at: datetime | None = None
    last_finished_at: datetime | None = None
    last_success_at: datetime | None = None
    last_duration_seconds: float | None = None
    last_exit_code: int | None = None
    last_category: str | None = None
    last_detail: str | None = None
    consecutive_failure_count: int = 0

    @property
    def active(self) -> bool:
        return self.active_cycle_id is not None

    @property
    def cycle_id(self) -> str | None:
        return self.active_cycle_id

    @property
    def active_cycle(self) -> str | None:
        return self.active_cycle_id

    @property
    def last_start_at(self) -> datetime | None:
        return self.last_started_at

    @property
    def last_finish_at(self) -> datetime | None:
        return self.last_finished_at

    @property
    def last_exit_category(self) -> str | None:
        return self.last_category

    @property
    def last_failure_category(self) -> str | None:
        return self.last_category

    @property
    def failure_count(self) -> int:
        return self.consecutive_failure_count

    @property
    def consecutive_failures(self) -> int:
        return self.consecutive_failure_count

    @property
    def duration_seconds(self) -> float | None:
        return self.last_duration_seconds

    @property
    def safe_detail(self) -> str | None:
        return self.last_detail


def validate_cycle_id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_CYCLE_ID_LENGTH:
        raise ValueError("cycle_id is missing or too long")
    if not _SAFE_TOKEN.fullmatch(value):
        raise ValueError("cycle_id contains unsupported characters")
    return value


def bounded_safe_detail(value: str | None) -> str | None:
    """Return a short, printable detail suitable for the health ledger."""

    if value is None:
        return None
    if not isinstance(value, str):
        return None
    cleaned = "".join(character if character.isprintable() else " " for character in value)
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None
    return cleaned[:MAX_SAFE_DETAIL_LENGTH]


__all__ = [
    "MAX_CYCLE_ID_LENGTH",
    "MAX_SAFE_DETAIL_LENGTH",
    "FIXED_RECEIVER_CONFIG_PATH",
    "FIXED_RECEIVER_MODULE",
    "DATASET_SYNC_CONFIG_PATH",
    "DATASET_SYNC_HEALTH_ID",
    "DATASET_SYNC_MODULE",
    "DatasetSyncConfig",
    "DatasetSyncHealth",
    "bounded_safe_detail",
    "validate_dataset_roots",
    "validate_cycle_id",
]

"""Configuration and bounded operational records for raw task synchronisation.

This module deliberately does not read Steward's TOML configuration.  Plan 006
owns loading these values into the daemon; keeping the value object independent
also makes it possible to validate a receiver boundary before a transfer.
"""

from __future__ import annotations

import math
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final


TASK_ARCHIVE_SYNC_HEALTH_ID: Final[str] = "task-archive-sync"
TASK_ARCHIVE_SYNC_MODULE: Final[str] = "steward-tasks"
TASK_ARCHIVE_SYNC_CONFIG_PATH: Final[str] = "/fixed/rsyncd.conf"
# Descriptive aliases used by operator-facing callers.
FIXED_RECEIVER_MODULE: Final[str] = TASK_ARCHIVE_SYNC_MODULE
FIXED_RECEIVER_CONFIG_PATH: Final[str] = TASK_ARCHIVE_SYNC_CONFIG_PATH
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


def _validate_source_root(path: Path) -> Path:
    if path is None:
        raise ValueError("tasks_dir must reference an existing directory")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("tasks_dir must be an absolute path")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ValueError("tasks_dir must reference an existing directory") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("tasks_dir must reference a regular non-symlink directory")
    return candidate.resolve()


def _validate_timeout(value: float, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > 86400:
        raise ValueError(f"{label} must be between 0 and 86400 seconds")
    return result


@dataclass(frozen=True, slots=True, init=False)
class TaskArchiveSyncConfig:
    """Fully explicit settings for one raw task-tree transfer.

    The receiver destination is intentionally not configurable.  A forced
    receiver confines the SSH command to its task root, and the client always
    sends the receiver-relative ``./`` destination.
    """

    enabled: bool
    tasks_dir: Path
    remote_user: str
    remote_host: str
    remote_port: int
    identity_path: Path
    known_hosts_path: Path
    receiver_module: str = TASK_ARCHIVE_SYNC_MODULE
    receiver_destination: str = TASK_ARCHIVE_SYNC_MODULE
    connect_timeout_seconds: float = 10.0
    transfer_timeout_seconds: float = 300.0

    def __init__(
        self,
        enabled: bool,
        tasks_dir: Path | None = None,
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
        source_root: Path | None = None,
        identity_file: Path | None = None,
        ssh_identity_path: Path | None = None,
        ssh_key_path: Path | None = None,
        known_hosts_file: Path | None = None,
        destination: str | None = None,
        receiver_module: str | None = None,
        module_name: str | None = None,
        module: str | None = None,
        fixed_receiver_module: str | None = None,
        whole_transfer_timeout_seconds: float | None = None,
        transfer_timeout: float | None = None,
    ) -> None:
        """Accept the repository's existing SSH path spellings as aliases."""

        selected_tasks = tasks_dir or source_task_root or source_root
        selected_identity = identity_path or identity_file or ssh_identity_path or ssh_key_path
        selected_known_hosts = known_hosts_path or known_hosts_file
        selected_destination = receiver_destination
        if destination is not None:
            selected_destination = destination
        module_values = [
            value
            for value in (
                receiver_module,
                module_name,
                module,
                fixed_receiver_module,
            )
            if value is not None
        ]
        selected_module = module_values[0] if module_values else TASK_ARCHIVE_SYNC_MODULE
        if any(value != selected_module for value in module_values):
            raise ValueError("receiver module aliases disagree")
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
        object.__setattr__(self, "remote_user", remote_user)
        object.__setattr__(self, "remote_host", remote_host)
        object.__setattr__(self, "remote_port", remote_port)
        object.__setattr__(self, "identity_path", selected_identity)
        object.__setattr__(self, "known_hosts_path", selected_known_hosts)
        # The receiver is a fixed daemon module.  Keep the old destination
        # spelling accepted only as an alias for that module so callers cannot
        # select a subpath or an arbitrary remote root.
        if selected_destination is not None and selected_destination not in {
            TASK_ARCHIVE_SYNC_MODULE,
            "./",
        }:
            raise ValueError("receiver destination is fixed to the task module")
        if selected_module != TASK_ARCHIVE_SYNC_MODULE:
            raise ValueError("receiver_module is fixed to the task archive module")
        object.__setattr__(self, "receiver_module", TASK_ARCHIVE_SYNC_MODULE)
        object.__setattr__(self, "receiver_destination", TASK_ARCHIVE_SYNC_MODULE)
        object.__setattr__(self, "connect_timeout_seconds", connect_timeout_seconds)
        object.__setattr__(self, "transfer_timeout_seconds", selected_transfer_timeout)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a boolean")
        source = _validate_source_root(self.tasks_dir)
        object.__setattr__(self, "tasks_dir", source)

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
        return self.receiver_module

    @property
    def whole_transfer_timeout_seconds(self) -> float:
        return self.transfer_timeout_seconds


@dataclass(frozen=True, slots=True)
class TaskArchiveSyncHealth:
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
    "TASK_ARCHIVE_SYNC_CONFIG_PATH",
    "TASK_ARCHIVE_SYNC_HEALTH_ID",
    "TASK_ARCHIVE_SYNC_MODULE",
    "TaskArchiveSyncConfig",
    "TaskArchiveSyncHealth",
    "bounded_safe_detail",
    "validate_cycle_id",
]
